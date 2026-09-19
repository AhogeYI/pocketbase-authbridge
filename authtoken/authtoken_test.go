package authtoken

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "authtoken-test-secret-0123456789abcdef" // 36 bytes

func TestSignParseRoundtrip(t *testing.T) {
	claims := NewClaims("authbridge", "user123", 30*time.Minute)
	token, err := Sign(claims, []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := Parse(token, []byte(testSecret), "authbridge")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Subject != "user123" {
		t.Errorf("subject = %q, want user123", parsed.Subject)
	}
	if parsed.Issuer != "authbridge" {
		t.Errorf("issuer = %q, want authbridge", parsed.Issuer)
	}
	if parsed.JWTID == "" {
		t.Error("jti is empty")
	}
	if time.Until(parsed.ExpiresAt) <= 0 || time.Until(parsed.ExpiresAt) > 31*time.Minute {
		t.Errorf("expiresAt out of range: %v", parsed.ExpiresAt)
	}
}

func TestParseRejectsExpired(t *testing.T) {
	claims := NewClaims("iss", "user1", -time.Minute)
	token, err := Sign(claims, []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(token, []byte(testSecret), "iss"); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestParseRejectsWrongSecret(t *testing.T) {
	token, err := Sign(NewClaims("iss", "user1", time.Minute), []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(token, []byte("another-secret-0123456789abcdef012345"), "iss"); err == nil {
		t.Fatal("token signed with a different secret accepted")
	}
}

func TestParseRejectsTamperedPayload(t *testing.T) {
	token, err := Sign(NewClaims("iss", "user1", time.Minute), []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(token, ".")
	parts[1] = parts[1] + "x" // corrupt the payload segment
	if _, err := Parse(strings.Join(parts, "."), []byte(testSecret), "iss"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestParseRejectsWrongIssuer(t *testing.T) {
	token, err := Sign(NewClaims("authbridge-a", "user1", time.Minute), []byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(token, []byte(testSecret), "authbridge-b"); err == nil {
		t.Fatal("token from a different issuer accepted")
	}
}

func TestParseRejectsAlgNone(t *testing.T) {
	// Hand-crafted unsigned token; WithValidMethods must reject it before any
	// key lookup, or the "alg": "none" classic would pass.
	noneToken := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJpc3MiLCJzdWIiOiJ1c2VyMSIsImV4cCI6OTk5OTk5OTk5OX0."
	if _, err := Parse(noneToken, []byte(testSecret), "iss"); err == nil {
		t.Fatal("alg=none token accepted")
	}
}

func TestSignRejectsWeakSecretAndEmptyIdentity(t *testing.T) {
	if _, err := Sign(NewClaims("iss", "u", time.Minute), []byte("short")); err == nil {
		t.Error("short secret accepted at sign time")
	}
	if _, err := Parse("x.y.z", []byte("short"), "iss"); err == nil {
		t.Error("short secret accepted at parse time")
	}
	if _, err := Sign(NewClaims("iss", "", time.Minute), []byte(testSecret)); err == nil {
		t.Error("empty subject accepted")
	}
	if _, err := Sign(NewClaims("", "u", time.Minute), []byte(testSecret)); err == nil {
		t.Error("empty issuer accepted")
	}
}

func TestParseClockLeeway(t *testing.T) {
	secret := []byte(testSecret)
	// Issued slightly in the future (verifier clock behind the issuer):
	// within the leeway this must parse.
	claims := NewClaims("iss", "user1", time.Minute)
	claims.IssuedAt = time.Now().Add(10 * time.Second)
	token, err := Sign(claims, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Parse(token, secret, "iss"); err != nil {
		t.Errorf("future iat within leeway rejected: %v", err)
	}

	// Issued beyond the leeway: rejected.
	claims.IssuedAt = time.Now().Add(5 * time.Minute)
	token, _ = Sign(claims, secret)
	if _, err := Parse(token, secret, "iss"); err == nil {
		t.Error("iat far in the future accepted")
	}

	// Just-expired (verifier clock ahead of the issuer): within the leeway.
	claims = NewClaims("iss", "user1", time.Minute)
	claims.ExpiresAt = time.Now().Add(-10 * time.Second)
	token, _ = Sign(claims, secret)
	if _, err := Parse(token, secret, "iss"); err != nil {
		t.Errorf("barely expired within leeway rejected: %v", err)
	}

	// Long expired: still rejected.
	claims.ExpiresAt = time.Now().Add(-5 * time.Minute)
	token, _ = Sign(claims, secret)
	if _, err := Parse(token, secret, "iss"); err == nil {
		t.Error("long expired token accepted")
	}
}
