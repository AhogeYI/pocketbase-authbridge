// Package authtoken signs and verifies short-lived service tokens:
// HS256 JWTs that carry a PocketBase user identity and nothing else, so the
// standalone services can authenticate requests offline (Supabase-style: one
// issuer signs, every resource server verifies with the shared secret — no
// call back to the identity plane per request).
//
// The package is deliberately dependency-light (golang-jwt only, no
// PocketBase): resource services import it without dragging the identity
// plane into their module graph. It is the wire contract between the
// authbridge PocketBase extension (issuer) and the services (verifiers).
package authtoken

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MinSecretLen is the smallest accepted signing secret. HS256 keys shorter
// than this are trivially brute-forceable from observed tokens.
const MinSecretLen = 32

// Claims is the full claim set of a service token. Identity only — no
// permissions, no PII beyond the user id: tokens end up in logs.
type Claims struct {
	Issuer    string // who signed (the authbridge instance)
	Subject   string // PocketBase user record id — the identity services act on
	IssuedAt  time.Time
	ExpiresAt time.Time
	JWTID     string // random; the hook for a future denylist
}

// NewClaims builds a claim set for subject with a fresh issue time, the given
// ttl and a random jti.
func NewClaims(issuer, subject string, ttl time.Duration) Claims {
	now := time.Now()
	return Claims{
		Issuer:    issuer,
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		JWTID:     randomID(),
	}
}

// Sign returns the HS256-signed JWT for the claims.
func Sign(claims Claims, secret []byte) (string, error) {
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	if claims.Subject == "" {
		return "", errors.New("authtoken: refusing to sign a token with an empty subject")
	}
	if claims.Issuer == "" {
		return "", errors.New("authtoken: refusing to sign a token with an empty issuer")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
		ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
		ID:        claims.JWTID,
	})
	return token.SignedString(secret)
}

// Parse verifies the signature (HS256 only), the expiry and the issuer, and
// returns the claims. A token signed with any other algorithm — including
// "none" — is rejected before the key is consulted.
func Parse(token string, secret []byte, issuer string) (*Claims, error) {
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	if issuer == "" {
		return nil, errors.New("authtoken: parse requires a non-empty expected issuer")
	}
	registered := jwt.RegisteredClaims{}
	parsed, err := jwt.ParseWithClaims(token, &registered, func(*jwt.Token) (any, error) {
		return secret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("authtoken: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("authtoken: token is not valid")
	}
	if registered.Subject == "" {
		return nil, errors.New("authtoken: token carries no subject")
	}
	return &Claims{
		Issuer:    registered.Issuer,
		Subject:   registered.Subject,
		IssuedAt:  registered.IssuedAt.Time,
		ExpiresAt: registered.ExpiresAt.Time,
		JWTID:     registered.ID,
	}, nil
}

func validateSecret(secret []byte) error {
	if len(secret) < MinSecretLen {
		return fmt.Errorf("authtoken: secret must be at least %d bytes, got %d", MinSecretLen, len(secret))
	}
	return nil
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is a broken runtime; a weak jti would silently
		// weaken any future denylist, so refuse instead.
		panic("authtoken: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
