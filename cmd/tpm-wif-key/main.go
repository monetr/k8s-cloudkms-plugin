// Binary tpm-wif-key provisions the TPM-resident signing key used by
// k8s-cloudkms-plugin and prints its public JWK set for upload to a Workload
// Identity Federation OIDC provider.
//
//	tpm-wif-key create   # generate + persist the key, print its JWKS
//	tpm-wif-key jwks     # print the JWKS of an existing key
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
	if len(os.Args) < 2 || (os.Args[1] != "create" && os.Args[1] != "jwks") {
		fmt.Fprintf(os.Stderr, "usage: %s create|jwks [-path-to-tpm /dev/tpmrm0] [-tpm-key-handle 0x%x]\n", os.Args[0], uint32(tpmkey.DefaultHandle))
		os.Exit(2)
	}
	cmd := os.Args[1]

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	pathToTPM := fs.String("path-to-tpm", "/dev/tpmrm0", "Path to the TPM resource manager device.")
	handleFlag := fs.String("tpm-key-handle", fmt.Sprintf("0x%x", uint32(tpmkey.DefaultHandle)), "Persistent handle for the signing key.")
	_ = fs.Parse(os.Args[2:])

	handle, err := strconv.ParseUint(*handleFlag, 0, 32)
	if err != nil {
		fatalf("invalid -tpm-key-handle %q: %v", *handleFlag, err)
	}

	tpm, err := linuxtpm.Open(*pathToTPM)
	if err != nil {
		fatalf("failed to open TPM %s: %v", *pathToTPM, err)
	}
	defer tpm.Close()

	var pub *ecdsa.PublicKey
	switch cmd {
	case "create":
		pub, err = tpmkey.Create(tpm, tpm2.TPMHandle(handle))
	case "jwks":
		pub, _, err = tpmkey.Public(tpm, tpm2.TPMHandle(handle))
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

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
