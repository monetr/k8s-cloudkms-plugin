package tpmkey

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Policy describes the boot state a signing key is bound to. The zero Policy
// means the key is not bound to anything: it can sign whenever the TPM is
// reachable, which is how keys were created before PCR binding existed.
//
// A bound key is created with UserWithAuth cleared, so the only way to use it
// is a policy session that satisfies its AuthPolicy. The policy is built, and
// must be satisfied, in this order:
//
//  1. If PCRSigner is set: TPM2_PolicyAuthorize, accepting any PCR policy
//     signed by PCRSigner (in practice PCR 11, signed for each UKI by ukify or
//     systemd-measure). Kernel updates need no new key.
//  2. If PCRs is set: TPM2_PolicyPCR over the values those PCRs held when the
//     key was created (in practice PCR 7). Changing them needs a new key.
type Policy struct {
	// PCRs (SHA-256 bank) bound to the values they had at creation.
	PCRs []uint
	// PCRSigner, if set, is the RSA public key whose signed PCR policies the
	// key accepts.
	PCRSigner *rsa.PublicKey
}

// Bound reports whether p binds a key to anything.
func (p Policy) Bound() bool { return len(p.PCRs) > 0 || p.PCRSigner != nil }

// pcrPolicyRetries bounds how often signing is retried when a PCR changes
// between TPM2_PolicyPCR and TPM2_Sign. The PCR update counter is global, so
// any extend (for example IMA on PCR 10) causes this, not just changes to the
// PCRs in the policy.
const pcrPolicyRetries = 3

// ParsePCRList parses a comma-separated list of PCR indices such as "7" or
// "7,11". It returns them sorted and deduplicated. An empty string is nil.
func ParsePCRList(s string) ([]uint, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var pcrs []uint
	for _, field := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(field), 10, 8)
		if err != nil || n > 23 {
			return nil, fmt.Errorf("invalid PCR %q: must be an integer from 0 to 23", strings.TrimSpace(field))
		}
		pcrs = append(pcrs, uint(n))
	}
	slices.Sort(pcrs)
	return slices.Compact(pcrs), nil
}

// ParseRSAPublicKeyPEM parses a PEM-encoded RSA public key in either PKIX
// ("PUBLIC KEY", what ukify and systemd write) or PKCS #1 ("RSA PUBLIC KEY")
// form.
func ParseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PCR-signing public key is not an RSA key (systemd only signs PCR policies with RSA)")
		}
		return rsaKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM block %q, want a public key", block.Type)
	}
}

// pcrSelection selects pcrs in the SHA-256 bank, encoded the way PC Client
// TPMs and systemd expect (a 3-byte bitmap for PCRs 0-23).
func pcrSelection(pcrs []uint) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
	}}}
}

// ReadPCRs returns the current SHA-256 values of pcrs, in the order given
// (which must be ascending, as ParsePCRList returns them).
//
// TPM2_PCRRead returns at most 8 values per call and may return fewer, so it
// is called until every PCR has been read. If any PCR changes in between, the
// values would be inconsistent, so it starts over.
func ReadPCRs(tpm transport.TPM, pcrs []uint) ([][]byte, error) {
	for range pcrPolicyRetries {
		values, consistent, err := readPCRsOnce(tpm, pcrs)
		if err != nil || consistent {
			return values, err
		}
	}
	return nil, errors.New("PCRs kept changing while being read")
}

func readPCRsOnce(tpm transport.TPM, pcrs []uint) ([][]byte, bool, error) {
	got := make(map[uint][]byte, len(pcrs))
	remaining := pcrs
	var counter uint32
	for first := true; len(remaining) > 0; first = false {
		rsp, err := tpm2.PCRRead{PCRSelectionIn: pcrSelection(remaining)}.Execute(tpm)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read PCRs %v: %w", remaining, err)
		}
		if first {
			counter = rsp.PCRUpdateCounter
		} else if rsp.PCRUpdateCounter != counter {
			return nil, false, nil
		}

		var returned []uint
		for _, sel := range rsp.PCRSelectionOut.PCRSelections {
			if sel.Hash != tpm2.TPMAlgSHA256 {
				continue
			}
			for i, b := range sel.PCRSelect {
				for bit := range 8 {
					if b&(1<<bit) != 0 {
						returned = append(returned, uint(i*8+bit))
					}
				}
			}
		}
		if len(returned) == 0 || len(returned) != len(rsp.PCRValues.Digests) {
			return nil, false, fmt.Errorf("TPM returned no SHA-256 values for PCR(s) %v; is the SHA-256 PCR bank allocated?", remaining)
		}
		for i, pcr := range returned {
			got[pcr] = rsp.PCRValues.Digests[i].Buffer
		}
		remaining = slices.DeleteFunc(slices.Clone(remaining), func(pcr uint) bool { return got[pcr] != nil })
	}

	values := make([][]byte, len(pcrs))
	for i, pcr := range pcrs {
		values[i] = got[pcr]
	}
	return values, true, nil
}

// checkNotReset refuses to bind a PCR that still holds its reset value. PCRs
// 0-15 reset to all zeros and 17-22 to all 0xFF. A PCR nothing has extended
// (for example PCR 11 when the host didn't boot a UKI through systemd-stub)
// matches every boot that also leaves it alone, so binding it adds nothing.
func checkNotReset(pcrs []uint, values [][]byte) error {
	for i, v := range values {
		if bytes.Equal(v, make([]byte, len(v))) || bytes.Equal(v, bytes.Repeat([]byte{0xff}, len(v))) {
			return fmt.Errorf("PCR %d still holds its reset value (%x), so nothing measured into it during boot; binding it would not protect anything", pcrs[i], v)
		}
	}
	return nil
}

// pcrPolicyDigest is the policy digest of a lone TPM2_PolicyPCR over pcrs
// holding values. That is also what systemd signs as "pol".
func pcrPolicyDigest(pcrs []uint, values [][]byte) ([]byte, error) {
	return authPolicy(Policy{PCRs: pcrs}, values)
}

// authPolicy is the AuthPolicy a key bound to p must carry, given the values
// p.PCRs must hold. It always starts from an empty policy: go-tpm's
// PolicyAuthorize.Update does not reset the calculator the way the TPM resets
// the session, so nothing may be fed in before it.
func authPolicy(p Policy, values [][]byte) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if p.PCRSigner != nil {
		name, err := signerName(p.PCRSigner)
		if err != nil {
			return nil, err
		}
		if err := (tpm2.PolicyAuthorize{KeySign: name}).Update(calc); err != nil {
			return nil, err
		}
	}
	if len(p.PCRs) > 0 {
		if len(values) != len(p.PCRs) {
			return nil, errors.New("PCR values do not match the PCR selection")
		}
		h := sha256.New()
		for _, v := range values {
			h.Write(v)
		}
		if err := (tpm2.PolicyPCR{
			Pcrs:      pcrSelection(p.PCRs),
			PcrDigest: tpm2.TPM2BDigest{Buffer: h.Sum(nil)},
		}).Update(calc); err != nil {
			return nil, err
		}
	}
	return calc.Hash().Digest, nil
}

// signerTemplate is the public area the PCR-signing key is loaded with to
// verify signed PCR policies. A bound key's AuthPolicy contains the Name of
// this exact structure, so it must never change: any change to it (attributes,
// scheme, exponent encoding, ...) would make every existing key unusable.
func signerTemplate(pub *rsa.PublicKey) tpm2.TPMTPublic {
	exponent := uint32(pub.E)
	if pub.E == 65537 {
		exponent = 0 // The TPM's encoding of the default exponent.
	}
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:  true,
			UserWithAuth: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits:   tpm2.TPMIRSAKeyBits(pub.N.BitLen()),
			Exponent:  exponent,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pub.N.Bytes()}),
	}
}

func signerName(pub *rsa.PublicKey) (tpm2.TPM2BName, error) {
	tmpl := signerTemplate(pub)
	name, err := tpm2.ObjectName(&tmpl)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("failed to compute the PCR-signing key's name: %w", err)
	}
	return *name, nil
}

// PublicKeyFingerprint is systemd's "pkfp" for pub: the SHA-256 of its PKCS #1
// DER encoding.
func PublicKeyFingerprint(pub *rsa.PublicKey) []byte {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	return sum[:]
}

// SignedPCRPolicy is one entry of a systemd PCR signature file: a TPM2
// PolicyPCR digest ("pol") over pcrs, signed by the key with fingerprint pkfp.
type SignedPCRPolicy struct {
	PCRs      []uint
	PKFP      []byte
	Policy    []byte
	Signature []byte
}

// ParseSignedPCRPolicies parses the JSON that systemd-measure and ukify embed
// in a UKI's .pcrsig section, and that systemd copies to
// /run/systemd/tpm2-pcr-signature.json:
//
//	{"sha256": [{"pcrs": [11], "pkfp": "<hex>", "pol": "<hex>", "sig": "<base64>"}, ...]}
//
// Only the sha256 bank is used. Other banks are signed over other digests.
func ParseSignedPCRPolicies(data []byte) ([]SignedPCRPolicy, error) {
	var banks map[string][]struct {
		PCRs []uint `json:"pcrs"`
		PKFP string `json:"pkfp"`
		Pol  string `json:"pol"`
		Sig  string `json:"sig"`
	}
	// A .pcrsig section extracted from a UKI may be NUL-padded.
	if err := json.Unmarshal(bytes.TrimRight(data, "\x00"), &banks); err != nil {
		return nil, fmt.Errorf("invalid PCR signature JSON: %w", err)
	}
	var out []SignedPCRPolicy
	for i, e := range banks["sha256"] {
		pkfp, err1 := hex.DecodeString(e.PKFP)
		pol, err2 := hex.DecodeString(e.Pol)
		sig, err3 := base64.StdEncoding.DecodeString(e.Sig)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, fmt.Errorf("invalid sha256 PCR signature entry %d: %w", i, err)
		}
		pcrs := slices.Clone(e.PCRs)
		slices.Sort(pcrs)
		if len(pcrs) == 0 || pcrs[len(pcrs)-1] > 23 || len(slices.Compact(slices.Clone(pcrs))) != len(pcrs) {
			return nil, fmt.Errorf("invalid sha256 PCR signature entry %d: bad PCR list %v", i, e.PCRs)
		}
		out = append(out, SignedPCRPolicy{PCRs: pcrs, PKFP: pkfp, Policy: pol, Signature: sig})
	}
	return out, nil
}

// ReadSignedPCRPolicies reads and parses a PCR signature file.
func ReadSignedPCRPolicies(path string) ([]SignedPCRPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signed PCR policies: %w", err)
	}
	return ParseSignedPCRPolicies(data)
}

// matchSignedPolicy returns the entry signed by signer whose policy matches
// the PCRs' current values. That is the policy approved for the booted UKI, in
// the boot phase the system is in now.
func matchSignedPolicy(tpm transport.TPM, signer *rsa.PublicKey, policies []SignedPCRPolicy) (*SignedPCRPolicy, error) {
	pkfp := PublicKeyFingerprint(signer)
	signedBySigner := 0
	for i := range policies {
		p := &policies[i]
		if !bytes.Equal(p.PKFP, pkfp) {
			continue
		}
		signedBySigner++
		values, err := ReadPCRs(tpm, p.PCRs)
		if err != nil {
			return nil, err
		}
		digest, err := pcrPolicyDigest(p.PCRs, values)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(digest, p.Policy) {
			return p, nil
		}
	}
	if signedBySigner == 0 {
		return nil, fmt.Errorf("no sha256 PCR policy is signed by the configured PCR-signing key (fingerprint %x); was the UKI built with its private key?", pkfp)
	}
	return nil, fmt.Errorf("none of the %d PCR policies signed by the configured key matches the current PCR values; this boot (UKI, or boot phase) was not signed for", signedBySigner)
}

// satisfyPolicy runs, in sess, the commands that satisfy a key bound to p.
// signed is the signed PCR policy to use when p.PCRSigner is set.
func satisfyPolicy(tpm transport.TPM, sess tpm2.Session, p Policy, signed *SignedPCRPolicy) error {
	if p.PCRSigner != nil {
		if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: pcrSelection(signed.PCRs)}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyPCR (signed PCRs %v) failed: %w", signed.PCRs, err)
		}

		// Load only the public key. It must be in the owner hierarchy: a key
		// in the null hierarchy yields a null ticket, which PolicyAuthorize
		// rejects.
		tmpl := signerTemplate(p.PCRSigner)
		loaded, err := tpm2.LoadExternal{InPublic: tpm2.New2B(tmpl), Hierarchy: tpm2.TPMRHOwner}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("failed to load the PCR-signing public key: %w", err)
		}
		defer tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(tpm)

		// systemd signs SHA-256(pol), which is PolicyAuthorize's
		// aHash = H(approvedPolicy || policyRef) with an empty policyRef.
		aHash := sha256.Sum256(signed.Policy)
		verified, err := tpm2.VerifySignature{
			KeyHandle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
			Digest:    tpm2.TPM2BDigest{Buffer: aHash[:]},
			Signature: tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSASSA,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: signed.Signature},
				}),
			},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("TPM rejected the signature on the PCR policy: %w", err)
		}

		if _, err := (tpm2.PolicyAuthorize{
			PolicySession:  sess.Handle(),
			ApprovedPolicy: tpm2.TPM2BDigest{Buffer: signed.Policy},
			KeySign:        loaded.Name,
			CheckTicket:    verified.Validation,
		}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyAuthorize failed: %w", err)
		}
	}
	if len(p.PCRs) > 0 {
		// An empty PcrDigest makes the TPM use the PCRs' current values; a
		// mismatch surfaces as TPM_RC_POLICY_FAIL when the key is used.
		if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: pcrSelection(p.PCRs)}).Execute(tpm); err != nil {
			return fmt.Errorf("PolicyPCR (PCRs %v) failed: %w", p.PCRs, err)
		}
	}
	return nil
}

// Check verifies that the key at handle is bound to exactly p, and that the
// current boot state satisfies it, so misconfiguration and PCR changes show
// up as a clear error rather than an opaque TPM failure. signed is only used
// when p.PCRSigner is set.
func Check(tpm transport.TPM, handle tpm2.TPMHandle, p Policy, signed []SignedPCRPolicy) error {
	info, err := Inspect(tpm, handle)
	if err != nil {
		return err
	}
	keyBound := len(info.AuthPolicy) > 0
	switch {
	case keyBound && !p.Bound():
		return fmt.Errorf("the key at handle 0x%x is bound to boot state, but no PCR policy is configured; pass the same PCRs and PCR-signing public key it was created with", uint32(handle))
	case !keyBound && p.Bound():
		return fmt.Errorf("a PCR policy is configured, but the key at handle 0x%x is not bound to boot state; create a new key with the policy", uint32(handle))
	case !keyBound:
		return nil
	}
	if info.UserWithAuth {
		return fmt.Errorf("the key at handle 0x%x can be used with its password, which bypasses its PCR policy; create a new key", uint32(handle))
	}

	var values [][]byte
	if len(p.PCRs) > 0 {
		if values, err = ReadPCRs(tpm, p.PCRs); err != nil {
			return err
		}
	}
	want, err := authPolicy(p, values)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, info.AuthPolicy) {
		return fmt.Errorf("the key at handle 0x%x does not match the configured policy: %s", uint32(handle), mismatchReason(p))
	}

	if p.PCRSigner != nil {
		if _, err := matchSignedPolicy(tpm, p.PCRSigner, signed); err != nil {
			return err
		}
	}
	return nil
}

func mismatchReason(p Policy) string {
	var parts []string
	if len(p.PCRs) > 0 {
		parts = append(parts, fmt.Sprintf("PCR(s) %v no longer hold the values the key was created with", p.PCRs))
	}
	if p.PCRSigner != nil {
		parts = append(parts, "the PCR-signing public key differs from the one the key was created with")
	}
	return strings.Join(parts, ", or ") + ", or the key was created with a different set of PCRs"
}
