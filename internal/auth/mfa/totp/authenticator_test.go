package totp

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func TestRFC6238SHA1Vectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, vector := range []struct {
		seconds int64
		code    string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		now := time.Unix(vector.seconds, 0)
		step, err := (Authenticator{}).Match(secret, vector.code, now, -1)
		if err != nil || step != vector.seconds/30 {
			t.Fatalf("vector %d: %d %v", vector.seconds, step, err)
		}
		if _, err := (Authenticator{}).Match(secret, vector.code, now, step); !errors.Is(err, domain.ErrInvalidCode) {
			t.Fatal("replay accepted", err)
		}
		if _, err := (Authenticator{}).Match(secret, vector.code, now.Add(2*time.Minute), -1); !errors.Is(err, domain.ErrInvalidCode) {
			t.Fatal("unbounded skew", err)
		}
	}
}

func TestAuthenticatorEnrollment(t *testing.T) {
	secret, uri, err := (Authenticator{}).Generate("Auth", "user-id")
	if err != nil || len(secret) != 52 {
		t.Fatal("secret size", len(secret), err)
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Query().Get("secret") != secret ||
		parsed.Query().Get("issuer") != "Auth" || parsed.Query().Get("period") != "30" || parsed.Query().Get("digits") != "6" {
		t.Fatal("URI contract", err)
	}
	if _, _, err := (Authenticator{}).Generate("", "user-id"); err == nil {
		t.Fatal("missing issuer")
	}
	if _, err := (Authenticator{}).Match("bad-secret!", "123456", time.Unix(59, 0), -1); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("corrupt secret", err)
	}
}
