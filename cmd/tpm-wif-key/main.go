// Binary tpm-wif-key provisions the TPM-resident signing key used by
// k8s-cloudkms-plugin and prints its public JWK set for upload to a Workload
// Identity Federation OIDC provider.
//
//	tpm-wif-key create   # generate + persist the key, print its JWKS
//	tpm-wif-key jwks     # print the JWKS of an existing key
//	tpm-wif-key check    # check the key's PCR policy against the current boot
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/monetr/k8s-cloudkms-plugin/tpmkey"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "create" && os.Args[1] != "jwks" && os.Args[1] != "check") {
		fmt.Fprintf(os.Stderr, "usage: %s create|jwks|check [-path-to-tpm /dev/tpmrm0] [-tpm-key-handle 0x%x] [-pcrs 7] [-pcr-public-key key.pem] [-pcr-signature file.json]\n", os.Args[0], uint32(tpmkey.DefaultHandle))
		os.Exit(2)
	}
	cmd := os.Args[1]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	pathToTPM := fs.String("path-to-tpm", "/dev/tpmrm0", "Path to the TPM resource manager device.")
	handleFlag := fs.String("tpm-key-handle", fmt.Sprintf("0x%x", uint32(tpmkey.DefaultHandle)), "Persistent handle for the signing key. Use 0x81008000-0x81008EFF (TCG Storage, Available); see the README.")
	pcrsFlag := fs.String("pcrs", "", "create/check: comma-separated PCRs (SHA-256 bank) to bind the key to at their current values, e.g. 7.")
	pcrPublicKey := fs.String("pcr-public-key", "", "create/check: PEM RSA public key or certificate; the key accepts PCR policies signed by it (systemd/ukify signed PCR 11 policies).")
	pcrSignature := fs.String("pcr-signature", "/run/systemd/tpm2-pcr-signature.json", "create/check: signed PCR policies for the booted UKI. Only used with -pcr-public-key.")
	_ = fs.Parse(os.Args[2:])

	handle, err := strconv.ParseUint(*handleFlag, 0, 32)
	if err != nil {
		fatalf("invalid -tpm-key-handle %q: %v", *handleFlag, err)
	}
	policy, err := parsePolicy(*pcrsFlag, *pcrPublicKey)
	if err != nil {
		fatalf("%v", err)
	}

	tpm, err := linuxtpm.Open(*pathToTPM)
	if err != nil {
		fatalf("failed to open TPM %s: %v", *pathToTPM, err)
	}
	defer tpm.Close()

	var pub *ecdsa.PublicKey
	switch cmd {
	case "create":
		// Refuse to persist a key this boot couldn't use: a wrong
		// -pcr-public-key or an unsigned boot would otherwise only show up at
		// `check` or plugin start, after the JWKS may already be uploaded.
		if policy.PCRSigner != nil {
			signed, err := tpmkey.ReadSignedPCRPolicies(*pcrSignature)
			if err != nil {
				fatalf("%v", err)
			}
			if err := tpmkey.CheckSignedPCRPolicies(tpm, policy.PCRSigner, signed); err != nil {
				fatalf("refusing to create a key the current boot can't use: %v", err)
			}
		}
		var values [][]byte
		pub, values, err = tpmkey.CreateWithPolicy(tpm, tpm2.TPMHandle(handle), policy)
		if err == nil {
			describePolicy(policy, values)
		}
	case "jwks":
		pub, _, err = tpmkey.Public(tpm, tpm2.TPMHandle(handle))
	case "check":
		var signed []tpmkey.SignedPCRPolicy
		if policy.PCRSigner != nil {
			if signed, err = tpmkey.ReadSignedPCRPolicies(*pcrSignature); err != nil {
				fatalf("%v", err)
			}
		}
		if err := tpmkey.Check(tpm, tpm2.TPMHandle(handle), policy, signed); err != nil {
			fatalf("%v", err)
		}
		fmt.Fprintf(os.Stderr, "key at handle 0x%x is usable in the current boot state\n", handle)
		return
	}
	if err != nil {
		fatalf("%v", err)
	}

	jwk, err := tpmkey.PublicJWK(pub)
	if err != nil {
		fatalf("%v", err)
	}
	out, err := tpmkey.JWKS(jwk)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Println(string(out))
}

func parsePolicy(pcrs, publicKeyPath string) (tpmkey.Policy, error) {
	var p tpmkey.Policy
	var err error
	if p.PCRs, err = tpmkey.ParsePCRList(pcrs); err != nil {
		return p, fmt.Errorf("invalid -pcrs: %w", err)
	}
	if publicKeyPath != "" {
		data, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return p, fmt.Errorf("failed to read -pcr-public-key: %w", err)
		}
		if p.PCRSigner, err = tpmkey.ParseRSAPublicKeyPEM(data); err != nil {
			return p, fmt.Errorf("invalid -pcr-public-key: %w", err)
		}
	}
	return p, nil
}

// describePolicy reports what a new key was bound to on stderr, keeping
// stdout clean for the JWKS.
func describePolicy(p tpmkey.Policy, values [][]byte) {
	if !p.Bound() {
		fmt.Fprintln(os.Stderr, "key is not bound to boot state")
		return
	}
	for i, pcr := range p.PCRs {
		fmt.Fprintf(os.Stderr, "bound to PCR %d (sha256) = %x\n", pcr, values[i])
	}
	if p.PCRSigner != nil {
		fmt.Fprintf(os.Stderr, "bound to PCR policies signed by RSA key with fingerprint %x\n", tpmkey.PublicKeyFingerprint(p.PCRSigner))
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
