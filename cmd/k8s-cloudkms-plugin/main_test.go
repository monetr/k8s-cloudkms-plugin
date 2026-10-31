package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/oauth2/google/externalaccount"

	"github.com/monetr/k8s-cloudkms-plugin/tpmkey"
)

const (
	testProvider       = "projects/123456789/locations/global/workloadIdentityPools/pool/providers/node-1"
	testIssuer         = "https://tpm.example.invalid"
	testSubject        = "node-1"
	testServiceAccount = "plugin@my-project.iam.gserviceaccount.com"
)

type borrowed struct{ transport.TPM }

func (borrowed) Close() error { return nil }

// fakeGoogle stands in for STS and IAM Credentials. Like the real STS, it only
// accepts a subject token whose signature verifies against the provider's
// JWKS and whose claims match the provider.
type fakeGoogle struct {
	t   *testing.T
	jwk tpmkey.JWK

	stsCalls, impersonationCalls int
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := f.t
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/token":
		f.stsCalls++
		if err := r.ParseForm(); err != nil {
			t.Errorf("STS: bad form: %v", err)
		}
		for field, want := range map[string]string{
			"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
			"audience":             "//iam.googleapis.com/" + testProvider,
			"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
			"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		} {
			if got := r.PostForm.Get(field); got != want {
				t.Errorf("STS: %s = %q, want %q", field, got, want)
			}
		}
		claims := verifyJWT(t, f.jwk, r.PostForm.Get("subject_token"))
		if claims["aud"] != "https://iam.googleapis.com/"+testProvider || claims["iss"] != testIssuer || claims["sub"] != testSubject {
			t.Errorf("STS: unexpected claims %v", claims)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "federated-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	case r.URL.Path == "/v1/projects/-/serviceAccounts/"+testServiceAccount+":generateAccessToken":
		f.impersonationCalls++
		if got := r.Header.Get("Authorization"); got != "Bearer federated-token" {
			t.Errorf("impersonation: Authorization = %q, want the federated token", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"accessToken": "impersonated-token",
			"expireTime":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	default:
		t.Errorf("unexpected request to %s", r.URL.Path)
		http.NotFound(w, r)
	}
}

func setup(t *testing.T) (func() (transport.TPMCloser, error), tpm2.TPMHandle, *fakeGoogle, *httptest.Server) {
	t.Helper()
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open TPM simulator: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })

	pub, err := tpmkey.Create(tpm, tpmkey.DefaultHandle)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := tpmkey.PublicJWK(pub)
	if err != nil {
		t.Fatal(err)
	}

	fake := &fakeGoogle{t: t, jwk: jwk}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	open := func() (transport.TPMCloser, error) { return borrowed{tpm}, nil }
	return open, tpmkey.DefaultHandle, fake, srv
}

func TestExternalAccountConfigDirect(t *testing.T) {
	open, handle, fake, srv := setup(t)

	conf := externalAccountConfig(open, handle, testProvider, testIssuer, testSubject, 5*time.Minute, "")
	if conf.ServiceAccountImpersonationURL != "" {
		t.Fatalf("impersonation configured without a service account: %s", conf.ServiceAccountImpersonationURL)
	}
	conf.TokenURL = srv.URL + "/v1/token"

	ts, err := externalaccount.NewTokenSource(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "federated-token" {
		t.Fatalf("got access token %q", token.AccessToken)
	}

	// The token is cached, so the TPM isn't asked to sign again.
	if _, err := ts.Token(); err != nil {
		t.Fatal(err)
	}
	if fake.stsCalls != 1 || fake.impersonationCalls != 0 {
		t.Fatalf("calls: sts=%d impersonation=%d, want 1/0", fake.stsCalls, fake.impersonationCalls)
	}
}

func TestExternalAccountConfigImpersonation(t *testing.T) {
	open, handle, fake, srv := setup(t)

	conf := externalAccountConfig(open, handle, testProvider, testIssuer, testSubject, 5*time.Minute, testServiceAccount)
	const wantURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + testServiceAccount + ":generateAccessToken"
	if conf.ServiceAccountImpersonationURL != wantURL {
		t.Fatalf("impersonation URL = %s, want %s", conf.ServiceAccountImpersonationURL, wantURL)
	}
	conf.TokenURL = srv.URL + "/v1/token"
	conf.ServiceAccountImpersonationURL = srv.URL + strings.TrimPrefix(wantURL, "https://iamcredentials.googleapis.com")

	ts, err := externalaccount.NewTokenSource(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "impersonated-token" {
		t.Fatalf("got access token %q", token.AccessToken)
	}
	if fake.stsCalls != 1 || fake.impersonationCalls != 1 {
		t.Fatalf("calls: sts=%d impersonation=%d, want 1/1", fake.stsCalls, fake.impersonationCalls)
	}
}

func verifyJWT(t *testing.T, jwk tpmkey.JWK, token string) map[string]any {
	t.Helper()
	enc := base64.RawURLEncoding
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("subject token has %d parts", len(parts))
	}
	x, _ := enc.DecodeString(jwk.X)
	y, _ := enc.DecodeString(jwk.Y)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := enc.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("subject token signature does not verify against the JWKS")
	}
	var claims map[string]any
	raw, _ := enc.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
