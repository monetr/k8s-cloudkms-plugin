package tpmkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/oauth2/google/externalaccount"
)

// openSimulator returns a freshly manufactured software TPM.
func openSimulator(t *testing.T) transport.TPMCloser {
	t.Helper()
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open TPM simulator: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })
	return tpm
}

// borrowed lets a JWTSupplier "open" and "close" a TPM the test owns.
type borrowed struct{ transport.TPM }

func (borrowed) Close() error { return nil }

func TestCreate(t *testing.T) {
	tpm := openSimulator(t)

	pub, err := Create(tpm, DefaultHandle)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("expected a P-256 key, got %s", pub.Curve.Params().Name)
	}

	got, _, err := Public(tpm, DefaultHandle)
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("Public returned a different key than Create")
	}

	if _, err := Create(tpm, DefaultHandle); err == nil {
		t.Fatal("Create overwrote an existing key")
	}
	got, _, err = Public(tpm, DefaultHandle)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("existing key changed after refused Create (err=%v)", err)
	}
}

func TestCreateDistinctKeys(t *testing.T) {
	tpm := openSimulator(t)

	a, err := Create(tpm, DefaultHandle)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(tpm, DefaultHandle+1)
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Fatal("two Create calls produced the same key")
	}
}

func TestPublicMissingKey(t *testing.T) {
	tpm := openSimulator(t)

	if _, _, err := Public(tpm, DefaultHandle); err == nil {
		t.Fatal("expected an error for an empty handle")
	}
}

func TestPublicRejectsUnsuitableKey(t *testing.T) {
	tpm := openSimulator(t)

	// A storage root key is a restricted decryption key, not a signing key.
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		PersistentHandle: DefaultHandle,
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}

	if _, _, err := Public(tpm, DefaultHandle); err == nil {
		t.Fatal("Public accepted a key that isn't an unrestricted signing key")
	}
}

func TestPublicJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Use != "sig" {
		t.Fatalf("unexpected JWK metadata: %+v", jwk)
	}

	enc := base64.RawURLEncoding
	raw, _ := key.PublicKey.Bytes() // 0x04 || X || Y
	if x, _ := enc.DecodeString(jwk.X); !bytes.Equal(x, raw[1:33]) {
		t.Fatal("x coordinate does not round-trip")
	}
	if y, _ := enc.DecodeString(jwk.Y); !bytes.Equal(y, raw[33:]) {
		t.Fatal("y coordinate does not round-trip")
	}

	// RFC 7638: SHA-256 over the required members, lexicographically ordered,
	// without whitespace. encoding/json sorts map keys, so it produces exactly
	// that form independently of the implementation under test.
	canonical, _ := json.Marshal(map[string]string{"crv": jwk.Crv, "kty": jwk.Kty, "x": jwk.X, "y": jwk.Y})
	sum := sha256.Sum256(canonical)
	if want := enc.EncodeToString(sum[:]); jwk.Kid != want {
		t.Fatalf("kid = %s, want RFC 7638 thumbprint %s", jwk.Kid, want)
	}
}

func TestPublicJWKRejectsOtherCurves(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicJWK(&key.PublicKey); err == nil {
		t.Fatal("expected P-384 to be rejected")
	}
}

func TestJWKS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := PublicJWK(&key.PublicKey)

	out, err := JWKS(jwk)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(out, &set); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0] != jwk {
		t.Fatalf("JWKS round-trip mismatch: %+v", set.Keys)
	}
}

func TestSubjectToken(t *testing.T) {
	tpm := openSimulator(t)
	pub, err := Create(tpm, DefaultHandle)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := PublicJWK(pub)
	verifier := keyFromJWK(t, jwk)

	s := &JWTSupplier{
		Open:     func() (transport.TPMCloser, error) { return borrowed{tpm}, nil },
		Handle:   DefaultHandle,
		Issuer:   "https://issuer.example.invalid",
		Subject:  "node-1",
		Audience: "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/node-1",
		Lifetime: 5 * time.Minute,
	}

	for i := range 50 {
		before := time.Now().Unix()
		token, err := s.SubjectToken(context.Background(), externalaccount.SupplierOptions{})
		if err != nil {
			t.Fatalf("SubjectToken: %v", err)
		}
		header, claims := verifyES256(t, verifier, token)

		if header["alg"] != "ES256" || header["typ"] != "JWT" || header["kid"] != jwk.Kid {
			t.Fatalf("token %d: unexpected header %v", i, header)
		}
		if claims["iss"] != s.Issuer || claims["sub"] != s.Subject || claims["aud"] != s.Audience {
			t.Fatalf("token %d: unexpected claims %v", i, claims)
		}
		iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
		if iat < before || iat > time.Now().Unix() || exp-iat != int64(s.Lifetime/time.Second) {
			t.Fatalf("token %d: bad iat/exp %d/%d", i, iat, exp)
		}
	}
}

func TestEncodeES256(t *testing.T) {
	// The simulator always returns full 32-byte values, so stripped ones (which
	// real TPMs may return) are covered here instead.
	r := bytes.Repeat([]byte{0xaa}, 31)
	s := []byte{0x01}
	got, err := encodeES256(r, s)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{0}, r...), append(make([]byte, 31), s...)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeES256 = %x, want %x", got, want)
	}

	if _, err := encodeES256(make([]byte, 33), s); err == nil {
		t.Fatal("accepted an oversized r")
	}
	if _, err := encodeES256(r, make([]byte, 33)); err == nil {
		t.Fatal("accepted an oversized s")
	}
}

func TestSubjectTokenRequiresConfig(t *testing.T) {
	for name, mutate := range map[string]func(*JWTSupplier){
		"issuer":   func(s *JWTSupplier) { s.Issuer = "" },
		"subject":  func(s *JWTSupplier) { s.Subject = "" },
		"audience": func(s *JWTSupplier) { s.Audience = "" },
		"lifetime": func(s *JWTSupplier) { s.Lifetime = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			s := &JWTSupplier{
				Open: func() (transport.TPMCloser, error) {
					t.Fatal("TPM opened despite invalid config")
					return nil, nil
				},
				Issuer:   "i",
				Subject:  "s",
				Audience: "a",
				Lifetime: time.Minute,
			}
			mutate(s)
			if _, err := s.SubjectToken(context.Background(), externalaccount.SupplierOptions{}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSubjectTokenMissingKey(t *testing.T) {
	tpm := openSimulator(t)
	s := &JWTSupplier{
		Open:     func() (transport.TPMCloser, error) { return borrowed{tpm}, nil },
		Handle:   DefaultHandle,
		Issuer:   "i",
		Subject:  "s",
		Audience: "a",
		Lifetime: time.Minute,
	}
	if _, err := s.SubjectToken(context.Background(), externalaccount.SupplierOptions{}); err == nil {
		t.Fatal("expected an error when no key is at the handle")
	}
}

// keyFromJWK rebuilds the verification key from the JWK alone, the way Google
// does from the provider's uploaded JWKS.
func keyFromJWK(t *testing.T, jwk JWK) *ecdsa.PublicKey {
	t.Helper()
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// verifyES256 checks token's signature and returns its decoded header and claims.
func verifyES256(t *testing.T, key *ecdsa.PublicKey, token string) (map[string]string, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	enc := base64.RawURLEncoding
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature is not 64 bytes of base64url (len=%d, err=%v)", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify against the JWK")
	}

	var header map[string]string
	var claims map[string]any
	rawHeader, _ := enc.DecodeString(parts[0])
	rawClaims, _ := enc.DecodeString(parts[1])
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		t.Fatal(err)
	}
	return header, claims
}
