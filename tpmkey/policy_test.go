package tpmkey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/oauth2/google/externalaccount"
)

const fixtureDir = "testdata/systemd-measure"

// extendPCR extends pcr in the SHA-256 bank with SHA-256(data), the way
// firmware and systemd-stub measure events.
func extendPCR(t *testing.T, tpm transport.TPM, pcr uint, data []byte) {
	t.Helper()
	digest := sha256.Sum256(data)
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256,
			Digest:  digest[:],
		}}},
	}).Execute(tpm); err != nil {
		t.Fatalf("PCRExtend(%d): %v", pcr, err)
	}
}

// bootUKI replays into PCR 11 what systemd-stub measures for the fixture UKI
// (each section's name, NUL-terminated, then its contents), followed by the
// systemd-pcrphase phase strings.
func bootUKI(t *testing.T, tpm transport.TPM, phases ...string) {
	t.Helper()
	for _, section := range []string{"linux", "osrel", "cmdline", "initrd"} {
		contents, err := os.ReadFile(filepath.Join(fixtureDir, section))
		if err != nil {
			t.Fatal(err)
		}
		extendPCR(t, tpm, 11, append([]byte("."+section), 0))
		extendPCR(t, tpm, 11, contents)
	}
	for _, phase := range phases {
		extendPCR(t, tpm, 11, []byte(phase))
	}
}

func fixtureSigner(t *testing.T) *rsa.PublicKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, "pcr-public-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseRSAPublicKeyPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// writeSignedPolicies signs, the way systemd-measure does, a PolicyPCR over
// pcrs at their current values, and writes it as a PCR signature file.
func writeSignedPolicies(t *testing.T, tpm transport.TPM, key *rsa.PrivateKey, pcrs []uint) string {
	t.Helper()
	values, err := ReadPCRs(tpm, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := pcrPolicyDigest(pcrs, values)
	if err != nil {
		t.Fatal(err)
	}
	aHash := sha256.Sum256(pol)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, aHash[:])
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"sha256": []map[string]any{{
		"pcrs": pcrs,
		"pkfp": hex.EncodeToString(PublicKeyFingerprint(&key.PublicKey)),
		"pol":  hex.EncodeToString(pol),
		"sig":  base64.StdEncoding.EncodeToString(sig),
	}}})
	path := filepath.Join(t.TempDir(), "tpm2-pcr-signature.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newSupplier(tpm transport.TPM, p Policy, signedPolicyPath string) *JWTSupplier {
	return &JWTSupplier{
		Open:                func() (transport.TPMCloser, error) { return borrowed{tpm}, nil },
		Handle:              DefaultHandle,
		Issuer:              "https://issuer.example.invalid",
		Subject:             "node-1",
		Audience:            "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/node-1",
		Lifetime:            5 * time.Minute,
		Policy:              p,
		SignedPCRPolicyPath: signedPolicyPath,
	}
}

// mustSign gets a token from s and checks it verifies against pub's JWK.
func mustSign(t *testing.T, s *JWTSupplier, pub *ecdsa.PublicKey) {
	t.Helper()
	token, err := s.SubjectToken(context.Background(), externalaccount.SupplierOptions{})
	if err != nil {
		t.Fatalf("SubjectToken: %v", err)
	}
	jwk, _ := PublicJWK(pub)
	verifyES256(t, keyFromJWK(t, jwk), token)
}

func signErr(s *JWTSupplier) error {
	_, err := s.SubjectToken(context.Background(), externalaccount.SupplierOptions{})
	return err
}

func TestParsePCRList(t *testing.T) {
	for in, want := range map[string][]uint{
		"":           nil,
		" ":          nil,
		"7":          {7},
		"11,7,7":     {7, 11},
		" 7 , 11 ":   {7, 11},
		"0,23":       {0, 23},
		"7,11,14,15": {7, 11, 14, 15},
	} {
		got, err := ParsePCRList(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ParsePCRList(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"24", "-1", "x", "7,", "7;11"} {
		if _, err := ParsePCRList(in); err == nil {
			t.Errorf("ParsePCRList(%q) accepted invalid input", in)
		}
	}
}

func TestParseRSAPublicKeyPEM(t *testing.T) {
	key := newRSAKey(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	if got, err := ParseRSAPublicKeyPEM(pkcs1); err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("PKCS #1: %v", err)
	}
	fixtureSigner(t) // PKIX, as written by openssl and ukify.

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if _, err := ParseRSAPublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Fatal("accepted an EC key")
	}
	if _, err := ParseRSAPublicKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("accepted non-PEM input")
	}
}

// selfSignedCertPEM returns a PEM certificate for pub, signed by priv. It
// expired an hour ago: only the key is used, so validity must not matter.
func selfSignedCertPEM(t *testing.T, pub crypto.PublicKey, priv crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "PCR signing"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// systemd and ukify setups that sign with PKCS #11 often keep the PCR-signing
// key as a certificate, so the public key may come as one.
func TestParseRSAPublicKeyPEMCertificate(t *testing.T) {
	key := newRSAKey(t)
	got, err := ParseRSAPublicKeyPEM(selfSignedCertPEM(t, &key.PublicKey, key))
	if err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("RSA certificate: %v", err)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRSAPublicKeyPEM(selfSignedCertPEM(t, &ec.PublicKey, ec)); err == nil || !strings.Contains(err.Error(), "not an RSA key") {
		t.Fatalf("expected an EC certificate to be rejected as not RSA, got %v", err)
	}
	if _, err := ParseRSAPublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})); err == nil {
		t.Fatal("accepted a malformed certificate")
	}
}

// CheckSignedPCRPolicies is what lets `tpm-wif-key create` refuse a key the
// current boot couldn't use, before anything is persisted.
func TestCheckSignedPCRPolicies(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	bootUKI(t, tpm, "enter-initrd", "leave-initrd", "sysinit", "ready")
	policies, err := ReadSignedPCRPolicies(filepath.Join(fixtureDir, "tpm2-pcr-signature.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := CheckSignedPCRPolicies(tpm, fixtureSigner(t), policies); err != nil {
		t.Fatalf("matching boot: %v", err)
	}

	wrong := newRSAKey(t)
	if err := CheckSignedPCRPolicies(tpm, &wrong.PublicKey, policies); err == nil || !strings.Contains(err.Error(), "no sha256 PCR policy is signed by the configured PCR-signing key") {
		t.Fatalf("expected a wrong signer to be rejected, got %v", err)
	}

	// Past "ready", as after shutdown starts, no signed phase matches.
	extendPCR(t, tpm, 11, []byte("shutdown"))
	if err := CheckSignedPCRPolicies(tpm, fixtureSigner(t), policies); err == nil || !strings.Contains(err.Error(), "matches the current PCR values") {
		t.Fatalf("expected an unsigned boot phase to be rejected, got %v", err)
	}
}

func TestCreateUnboundKeepsTemplate(t *testing.T) {
	tpm := openSimulator(t)
	if _, err := Create(tpm, DefaultHandle); err != nil {
		t.Fatal(err)
	}
	rsp, err := tpm2.ReadPublic{ObjectHandle: DefaultHandle}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := rsp.OutPublic.Contents()
	if len(public.AuthPolicy.Buffer) != 0 || public.ObjectAttributes != signingTemplate.ObjectAttributes {
		t.Fatalf("unbound key differs from the original template: policy %x, attributes %+v", public.AuthPolicy.Buffer, public.ObjectAttributes)
	}
}

func TestCreateWithPCRs(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	extendPCR(t, tpm, 11, []byte("uki"))

	_, values, err := CreateWithPolicy(tpm, DefaultHandle, Policy{PCRs: []uint{7, 11}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(tpm, DefaultHandle)
	if err != nil {
		t.Fatal(err)
	}
	if info.UserWithAuth {
		t.Fatal("bound key can still be used with its password")
	}

	// TPM 2.0 Part 3, TPM2_PolicyPCR, built by hand rather than with go-tpm:
	// H(0^32 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || H(PCR7 || PCR11)).
	pcrDigest := sha256.Sum256(append(slices.Clone(values[0]), values[1]...))
	var buf bytes.Buffer
	buf.Write(make([]byte, 32))
	binary.Write(&buf, binary.BigEndian, uint32(tpm2.TPMCCPolicyPCR))
	binary.Write(&buf, binary.BigEndian, uint32(1))                 // one bank
	binary.Write(&buf, binary.BigEndian, uint16(tpm2.TPMAlgSHA256)) // SHA-256
	buf.Write([]byte{3, 0x80, 0x08, 0x00})                          // PCRs 7 and 11
	buf.Write(pcrDigest[:])
	want := sha256.Sum256(buf.Bytes())
	if !bytes.Equal(info.AuthPolicy, want[:]) {
		t.Fatalf("AuthPolicy = %x, want %x", info.AuthPolicy, want)
	}
}

func TestPolicyDigestMatchesTPM(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	extendPCR(t, tpm, 11, []byte("uki"))
	pcrs := []uint{7, 11}

	sess, closeSession, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSession()
	if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: pcrSelection(pcrs)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	got, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}

	values, _ := ReadPCRs(tpm, pcrs)
	want, _ := authPolicy(Policy{PCRs: pcrs}, values)
	if !bytes.Equal(got.PolicyDigest.Buffer, want) {
		t.Fatalf("TPM computed %x, authPolicy computed %x", got.PolicyDigest.Buffer, want)
	}
}

func TestReadPCRsMoreThanEight(t *testing.T) {
	tpm := openSimulator(t)
	var pcrs []uint
	for pcr := range uint(16) {
		extendPCR(t, tpm, pcr, []byte{byte(pcr)})
		pcrs = append(pcrs, pcr)
	}

	// TPM2_PCRRead returns at most 8 digests, so this needs several reads.
	values, err := ReadPCRs(tpm, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	for i, pcr := range pcrs {
		one, err := ReadPCRs(tpm, []uint{pcr})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(values[i], one[0]) {
			t.Fatalf("PCR %d: %x read in a batch, %x alone", pcr, values[i], one[0])
		}
	}
}

func TestCreateRefusesResetPCR(t *testing.T) {
	tpm := openSimulator(t)
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, Policy{PCRs: []uint{7}}); err == nil || !strings.Contains(err.Error(), "reset value") {
		t.Fatalf("expected a reset-value error, got %v", err)
	}
	if _, _, err := Public(tpm, DefaultHandle); err == nil {
		t.Fatal("a key was persisted despite the error")
	}

	if err := checkNotReset([]uint{17}, [][]byte{bytes.Repeat([]byte{0xff}, 32)}); err == nil {
		t.Fatal("accepted an all-0xFF PCR")
	}
}

func TestSubjectTokenWithPCRPolicy(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	p := Policy{PCRs: []uint{7}}
	pub, _, err := CreateWithPolicy(tpm, DefaultHandle, p)
	if err != nil {
		t.Fatal(err)
	}
	s := newSupplier(tpm, p, "")
	mustSign(t, s, pub)
	if err := Check(tpm, DefaultHandle, p, nil); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// Another boot state (a dbx update, Secure Boot turned off, ...).
	extendPCR(t, tpm, 7, []byte("something else"))
	err = signErr(s)
	if !errors.Is(err, tpm2.TPMRCPolicyFail) || !strings.Contains(err.Error(), "PCR(s) [7]") {
		t.Fatalf("expected a policy failure naming PCR 7, got %v", err)
	}
	if err := Check(tpm, DefaultHandle, p, nil); err == nil {
		t.Fatal("Check passed after PCR 7 changed")
	}
}

func TestBoundKeyRejectsPassword(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, Policy{PCRs: []uint{7}}); err != nil {
		t.Fatal(err)
	}
	_, name, err := Public(tpm, DefaultHandle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := sign(tpm, DefaultHandle, name, digest[:], Policy{}, nil); !errors.Is(err, tpm2.TPMRCAuthUnavailable) {
		t.Fatalf("password auth on a bound key: expected TPM_RC_AUTH_UNAVAILABLE, got %v", err)
	}
}

func TestCheckConfigMismatch(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	extendPCR(t, tpm, 11, []byte("uki"))
	unbound, bound := DefaultHandle, DefaultHandle+1
	if _, err := Create(tpm, unbound); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateWithPolicy(tpm, bound, Policy{PCRs: []uint{7}}); err != nil {
		t.Fatal(err)
	}

	if err := Check(tpm, unbound, Policy{}, nil); err != nil {
		t.Errorf("unbound key, no policy: %v", err)
	}
	for name, tc := range map[string]struct {
		handle tpm2.TPMHandle
		p      Policy
	}{
		"policy configured for unbound key":   {unbound, Policy{PCRs: []uint{7}}},
		"no policy configured for bound key":  {bound, Policy{}},
		"different PCRs than at creation":     {bound, Policy{PCRs: []uint{11}}},
		"signer configured but not at create": {bound, Policy{PCRs: []uint{7}, PCRSigner: fixtureSigner(t)}},
	} {
		if err := Check(tpm, tc.handle, tc.p, nil); err == nil {
			t.Errorf("%s: Check passed", name)
		}
	}
}

func TestSystemdFixtureFingerprint(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtureDir, "tpm2-pcr-signature.json"))
	if err != nil {
		t.Fatal(err)
	}
	policies, err := ParseSignedPCRPolicies(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 sha256 entries, got %d", len(policies))
	}
	// As extracted from a UKI's .pcrsig section with objcopy.
	if padded, err := ParseSignedPCRPolicies(append(data, 0, 0, 0)); err != nil || len(padded) != 2 {
		t.Fatalf("NUL-padded file: %d entries, %v", len(padded), err)
	}
	want := PublicKeyFingerprint(fixtureSigner(t))
	for _, p := range policies {
		if !bytes.Equal(p.PKFP, want) || !slices.Equal(p.PCRs, []uint{11}) {
			t.Fatalf("entry %+v: want pkfp %x and PCRs [11]", p, want)
		}
	}
}

// TestSystemdSignedPolicy uses a PCR policy signed by real systemd-measure,
// so it checks compatibility with systemd's format, digest and signature, not
// just with this package's reading of them.
func TestSystemdSignedPolicy(t *testing.T) {
	for _, phases := range [][]string{
		{"enter-initrd", "leave-initrd", "sysinit", "ready"}, // systemd-based initrd
		{"sysinit", "ready"}, // initrd without systemd-pcrphase
	} {
		t.Run(strings.Join(phases, ":"), func(t *testing.T) {
			tpm := openSimulator(t)
			extendPCR(t, tpm, 7, []byte("secure boot state"))
			bootUKI(t, tpm, phases...)

			p := Policy{PCRs: []uint{7}, PCRSigner: fixtureSigner(t)}
			pub, _, err := CreateWithPolicy(tpm, DefaultHandle, p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixtureDir, "tpm2-pcr-signature.json")
			policies, err := ReadSignedPCRPolicies(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(tpm, DefaultHandle, p, policies); err != nil {
				t.Fatalf("Check: %v", err)
			}
			s := newSupplier(tpm, p, path)
			mustSign(t, s, pub)

			// Shutting down, or soft-rebooting, moves PCR 11 past "ready".
			extendPCR(t, tpm, 11, []byte("shutdown"))
			if err := signErr(s); err == nil || !strings.Contains(err.Error(), "matches the current PCR values") {
				t.Fatalf("expected no signed policy to match, got %v", err)
			}
		})
	}
}

func TestSystemdSignedPolicyRequiresPCR7(t *testing.T) {
	tpm := openSimulator(t)
	extendPCR(t, tpm, 7, []byte("secure boot state"))
	bootUKI(t, tpm, "enter-initrd", "leave-initrd", "sysinit", "ready")
	p := Policy{PCRs: []uint{7}, PCRSigner: fixtureSigner(t)}
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, p); err != nil {
		t.Fatal(err)
	}

	// The UKI is still signed for, but the Secure Boot state changed.
	extendPCR(t, tpm, 7, []byte("something else"))
	err := signErr(newSupplier(tpm, p, filepath.Join(fixtureDir, "tpm2-pcr-signature.json")))
	if !errors.Is(err, tpm2.TPMRCPolicyFail) {
		t.Fatalf("expected a policy failure, got %v", err)
	}
}

// TestSignedPolicyNewKernel is the point of signed policies: a new UKI changes
// PCR 11, and a policy signed for it keeps the same key working.
func TestSignedPolicyNewKernel(t *testing.T) {
	tpm := openSimulator(t)
	signer := newRSAKey(t)
	p := Policy{PCRSigner: &signer.PublicKey}
	extendPCR(t, tpm, 11, []byte("kernel 6.12.1"))
	pub, _, err := CreateWithPolicy(tpm, DefaultHandle, p)
	if err != nil {
		t.Fatal(err)
	}
	oldPolicy := writeSignedPolicies(t, tpm, signer, []uint{11})
	mustSign(t, newSupplier(tpm, p, oldPolicy), pub)

	// The simulator can't reboot without losing the key, so stand in for
	// "booted a different UKI" by moving PCR 11 to another value.
	extendPCR(t, tpm, 11, []byte("kernel 6.12.2"))
	if err := signErr(newSupplier(tpm, p, oldPolicy)); err == nil {
		t.Fatal("the old kernel's signed policy still works")
	}
	newPolicy := writeSignedPolicies(t, tpm, signer, []uint{11})
	mustSign(t, newSupplier(tpm, p, newPolicy), pub)
}

func TestSignedPolicyUntrustedSigner(t *testing.T) {
	tpm := openSimulator(t)
	trusted, attacker := newRSAKey(t), newRSAKey(t)
	extendPCR(t, tpm, 11, []byte("kernel"))
	p := Policy{PCRSigner: &trusted.PublicKey}
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, p); err != nil {
		t.Fatal(err)
	}

	// A policy signed by another key, presented as its own.
	path := writeSignedPolicies(t, tpm, attacker, []uint{11})
	if err := signErr(newSupplier(tpm, p, path)); err == nil || !strings.Contains(err.Error(), "no sha256 PCR policy is signed by the configured") {
		t.Fatalf("expected the attacker's policy to be ignored, got %v", err)
	}

	// The attacker's key, configured as if it were trusted: the key's
	// AuthPolicy pins the trusted key, so this must fail in the TPM too.
	evil := Policy{PCRSigner: &attacker.PublicKey}
	if err := Check(tpm, DefaultHandle, evil, nil); err == nil {
		t.Fatal("Check accepted a different PCR-signing key")
	}
	if err := signErr(newSupplier(tpm, evil, path)); !errors.Is(err, tpm2.TPMRCPolicyFail) {
		t.Fatalf("expected the TPM to refuse, got %v", err)
	}
}

func TestSignedPolicyForgedSignature(t *testing.T) {
	tpm := openSimulator(t)
	signer := newRSAKey(t)
	extendPCR(t, tpm, 11, []byte("kernel"))
	p := Policy{PCRSigner: &signer.PublicKey}
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, p); err != nil {
		t.Fatal(err)
	}

	// Right fingerprint and policy, wrong signature.
	path := writeSignedPolicies(t, tpm, signer, []uint{11})
	data, _ := os.ReadFile(path)
	var file map[string][]map[string]any
	json.Unmarshal(data, &file)
	sig, _ := base64.StdEncoding.DecodeString(file["sha256"][0]["sig"].(string))
	sig[len(sig)/2] ^= 0xff
	file["sha256"][0]["sig"] = base64.StdEncoding.EncodeToString(sig)
	data, _ = json.Marshal(file)
	os.WriteFile(path, data, 0o600)

	if err := signErr(newSupplier(tpm, p, path)); err == nil || !strings.Contains(err.Error(), "rejected the signature") {
		t.Fatalf("expected the TPM to reject the signature, got %v", err)
	}
}

func TestSignedPolicyMissingFile(t *testing.T) {
	tpm := openSimulator(t)
	signer := newRSAKey(t)
	extendPCR(t, tpm, 11, []byte("kernel"))
	p := Policy{PCRSigner: &signer.PublicKey}
	if _, _, err := CreateWithPolicy(tpm, DefaultHandle, p); err != nil {
		t.Fatal(err)
	}
	if err := signErr(newSupplier(tpm, p, filepath.Join(t.TempDir(), "missing.json"))); err == nil {
		t.Fatal("signed without a signed policy file")
	}
}
