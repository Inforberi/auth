package authjwt

import (
	"errors"
	"testing"
	"time"
)

func TestIssuerVerifierPinnedPolicies(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, rawKeys := testKey(t, "current")
	keys, err := ParsePublicKeys(rawKeys)
	if err != nil {
		t.Fatal(err)
	}
	policies := []Expectations{{Issuer: "https://auth.example", Audience: "orders", Mode: Strict}, {Issuer: "https://auth.example", Audience: "reports", Mode: Local}}
	v, err := NewIssuerVerifier(policies, keys)
	if err != nil {
		t.Fatal(err)
	}
	policies[0].Mode = Local
	for _, audience := range []string{"orders", "reports"} {
		claims := testClaims(now)
		claims.Audience = audience
		if audience == "reports" {
			claims.Mode = Local
		}
		if _, err := v.VerifySignature(t.Context(), signedClaims(t, key, claims), now); err != nil {
			t.Fatal(err)
		}
		claims.Mode = map[string]string{Strict: Local, Local: Strict}[claims.Mode]
		if _, err := v.VerifySignature(t.Context(), signedClaims(t, key, claims), now); !errors.Is(err, ErrInvalidToken) {
			t.Fatal("mode accepted", err)
		}
	}
	for name, mutate := range map[string]func(*Claims){
		"issuer":   func(c *Claims) { c.Issuer = "https://evil.example" },
		"audience": func(c *Claims) { c.Audience = "unknown" },
		"expiry":   func(c *Claims) { c.ExpiresAt = now.Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			c := testClaims(now)
			mutate(&c)
			if _, err := v.VerifySignature(t.Context(), signedClaims(t, key, c), now); !errors.Is(err, ErrInvalidToken) {
				t.Fatal(err)
			}
		})
	}
	// The issuer's keyset is deployment-pinned, not a remote fetch with a fabricated refresh time.
	future := now.Add(2 * time.Hour)
	if _, err := v.VerifySignature(t.Context(), signedClaims(t, key, testClaims(future)), future); err != nil {
		t.Fatal(err)
	}
	v.admission = make(chan struct{}, 1)
	v.admission <- struct{}{}
	if _, err := v.VerifySignature(t.Context(), "invalid", now); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	for _, invalid := range [][]Expectations{nil, {policies[0], policies[0]}, {{Issuer: "http://auth.example", Audience: "orders", Mode: Strict}}} {
		if _, err := NewIssuerVerifier(invalid, keys); err == nil {
			t.Fatal("invalid pinned policy accepted")
		}
	}
}
