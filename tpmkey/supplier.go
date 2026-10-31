package tpmkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/oauth2/google/externalaccount"
)

// JWTSupplier implements externalaccount.SubjectTokenSupplier by minting an
// ES256 JWT signed by the TPM-resident key. The JWT only ever exists in memory
// on its way to Google's STS endpoint.
type JWTSupplier struct {
	// Open returns a connection to the TPM; it is closed after each signature.
	Open func() (transport.TPMCloser, error)
	// Handle is the persistent handle of the signing key.
	Handle tpm2.TPMHandle
	// Issuer is the `iss` claim; it must match the provider's --issuer-uri.
	Issuer string
	// Subject is the `sub` claim, typically mapped to google.subject.
	Subject string
	// Audience is the `aud` claim; the provider's allowed audience.
	Audience string
	// Lifetime of each JWT. Only needs to outlive the STS exchange. At most
	// MaxLifetime.
	Lifetime time.Duration

	mu sync.Mutex
}

// MaxLifetime is the longest lifetime a JWT may be signed with. A leaked JWT
// can be exchanged for access tokens until it expires, so this bounds how long
// one stays useful.
const MaxLifetime = time.Hour

var _ externalaccount.SubjectTokenSupplier = (*JWTSupplier)(nil)

// SubjectToken signs and returns a fresh JWT.
func (s *JWTSupplier) SubjectToken(ctx context.Context, _ externalaccount.SupplierOptions) (string, error) {
	if s.Issuer == "" || s.Subject == "" || s.Audience == "" {
		return "", errors.New("tpmkey: issuer, subject and audience must all be set")
	}
	if s.Lifetime <= 0 || s.Lifetime > MaxLifetime {
		return "", fmt.Errorf("tpmkey: lifetime must be positive and at most %s", MaxLifetime)
	}

	// TPM transports are not safe for concurrent use.
	s.mu.Lock()
	defer s.mu.Unlock()

	tpm, err := s.Open()
	if err != nil {
		return "", fmt.Errorf("tpmkey: failed to open TPM: %w", err)
	}
	defer tpm.Close()

	pub, name, err := Public(tpm, s.Handle)
	if err != nil {
		return "", fmt.Errorf("tpmkey: %w", err)
	}
	jwk, err := PublicJWK(pub)
	if err != nil {
		return "", fmt.Errorf("tpmkey: %w", err)
	}

	issuedAt := time.Now()
	header, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": jwk.Kid,
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": s.Issuer,
		"sub": s.Subject,
		"aud": s.Audience,
		"iat": issuedAt.Unix(),
		"exp": issuedAt.Add(s.Lifetime).Unix(),
	})
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := sign(tpm, s.Handle, name, digest[:])
	if err != nil {
		return "", fmt.Errorf("tpmkey: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}
