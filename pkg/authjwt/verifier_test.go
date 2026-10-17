package authjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func testKey(t testing.TB, kid string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	return key, raw
}

func testClaims(now time.Time) Claims {
	return Claims{
		Issuer: "https://auth.example", Subject: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222",
		Audience: "orders", IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), ID: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		AuthVersion: 1, Scope: "orders.read", Mode: Strict, AuthTime: now.Add(-time.Minute).Unix(), Methods: []string{"pwd"},
	}
}

func signPayload(t testing.TB, key *ecdsa.PrivateKey, kid string, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	message, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := message.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signedClaims(t testing.TB, key *ecdsa.PrivateKey, c Claims) string {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return signPayload(t, key, "current", data)
}

func fixtureVerifier(t testing.TB, jwks []byte, now time.Time) *Verifier {
	t.Helper()
	keys, err := ParsePublicKeys(jwks)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: Strict}, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestClaimsAndVerification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, jwks := testKey(t, "current")
	v := fixtureVerifier(t, jwks, now)
	base := testClaims(now)
	for name, mutate := range map[string]func(*Claims){
		"issuer":           func(c *Claims) { c.Issuer = "https://other.example" },
		"audience":         func(c *Claims) { c.Audience = "payments" },
		"mode":             func(c *Claims) { c.Mode = Local },
		"expired":          func(c *Claims) { c.ExpiresAt = now.Unix() },
		"too long":         func(c *Claims) { c.ExpiresAt = c.IssuedAt + 301 },
		"future":           func(c *Claims) { c.IssuedAt = now.Unix() + 31 },
		"missing time":     func(c *Claims) { c.IssuedAt = 0 },
		"negative time":    func(c *Claims) { c.IssuedAt = -1 },
		"huge time":        func(c *Claims) { c.ExpiresAt = 1<<63 - 1 },
		"UUID":             func(c *Claims) { c.Subject = "../user" },
		"nil session":      func(c *Claims) { c.SessionID = "00000000-0000-0000-0000-000000000000" },
		"jti":              func(c *Claims) { c.ID = "short" },
		"auth version":     func(c *Claims) { c.AuthVersion = 0 },
		"scope duplicate":  func(c *Claims) { c.Scope = "orders.read orders.read" },
		"scope unsorted":   func(c *Claims) { c.Scope = "orders.write orders.read" },
		"scope whitespace": func(c *Claims) { c.Scope = " orders.read" },
		"scope wildcard":   func(c *Claims) { c.Scope = "orders.*" },
		"scope size":       func(c *Claims) { c.Scope = strings.Repeat("a", 2049) },
		"unknown method":   func(c *Claims) { c.Methods = []string{"admin"} },
		"two primaries":    func(c *Claims) { c.Methods = []string{"pwd", "oidc"} },
		"missing primary":  func(c *Claims) { c.Methods = nil },
		"false MFA":        func(c *Claims) { c.Methods = []string{"pwd", "otp"} },
		"future proof":     func(c *Claims) { c.AuthTime = c.IssuedAt + 1 },
		"future nbf":       func(c *Claims) { n := now.Unix() + 31; c.NotBefore = &n },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := v.VerifySignature(t.Context(), signedClaims(t, key, c), now); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("accepted", err)
			}
		})
	}
	for _, mode := range []string{Strict, Local} {
		c := base
		c.Mode = mode
		keys, _ := ParsePublicKeys(jwks)
		verifier, err := NewVerifier(Expectations{Issuer: base.Issuer, Audience: base.Audience, Mode: mode}, keys, now)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := verifier.VerifySignature(t.Context(), signedClaims(t, key, c), now); err != nil || got.Scope != base.Scope {
			t.Fatal(got, err)
		}
	}
	valid := signedClaims(t, key, base)
	if _, err := v.VerifySignature(t.Context(), valid, now.Add(MaxKeyAge)); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatal("expired trust", err)
	}
	if _, err := v.VerifySignature(t.Context(), valid, now.Add(-time.Second)); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatal("future trust", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.VerifySignature(ctx, valid, now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for range cap(v.admission) {
		v.admission <- struct{}{}
	}
	if _, err := v.VerifySignature(t.Context(), valid, now); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded admission", err)
	}
}

func TestSignedAmbiguousPayloads(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, jwks := testKey(t, "current")
	v := fixtureVerifier(t, jwks, now)
	data, _ := json.Marshal(testClaims(now))
	for name, payload := range map[string]string{
		"duplicate":      strings.Replace(string(data), `"auth_version":1`, `"auth_version":1,"auth_version":2`, 1),
		"case":           strings.Replace(string(data), `"iss":`, `"ISS":`, 1),
		"null optional":  strings.TrimSuffix(string(data), "}") + `,"nbf":null}`,
		"fraction":       strings.Replace(string(data), `"auth_version":1`, `"auth_version":1.0`, 1),
		"array audience": strings.Replace(string(data), `"aud":"orders"`, `"aud":["orders"]`, 1),
		"unknown":        strings.TrimSuffix(string(data), "}") + `,"roles":["admin"]}`,
		"nested":         `{"iss":` + strings.Repeat("[", 1000) + `0` + strings.Repeat("]", 1000) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.VerifySignature(t.Context(), signPayload(t, key, "current", []byte(payload)), now); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("accepted", err)
			}
		})
	}
	other, _ := testKey(t, "current")
	if _, err := v.VerifySignature(t.Context(), signedClaims(t, other, testClaims(now)), now); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("wrong key accepted", err)
	}
}

func TestCompactHeaders(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	for _, header := range []string{
		`{"alg":"none","kid":"current","typ":"at+jwt"}`, `{"alg":"HS256","kid":"current","typ":"at+jwt"}`,
		`{"alg":"ES256","kid":"current","typ":"JWT"}`, `{"alg":"ES256","kid":"current","kid":"other","typ":"at+jwt"}`,
		`{"alg":"ES256","kid":"../key","typ":"at+jwt"}`, `{"alg":"ES256","kid":"current","typ":"at+jwt","crit":[]}`,
		`{"alg":"ES256","kid":"current","typ":"at+jwt","jku":"https://evil.test"}`, `{"ALG":"ES256","kid":"current","typ":"at+jwt"}`,
		`{"alg":"ES256","kid":null,"typ":"at+jwt"}`, `{"alg":"ES256","kid":"current","typ":"at+jwt","b64":false}`,
	} {
		if _, err := checkCompact(base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + payload + "." + sig); err == nil {
			t.Fatal("accepted header", header)
		}
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"current","typ":"at+jwt"}`))
	for _, raw := range []string{"", strings.Repeat("x", MaxTokenBytes+1), header + ".." + sig, header + "." + payload + "." + sig + ".", header + "\n." + payload + "." + sig, header + "=." + payload + "." + sig, header + "." + payload + ".AA"} {
		if _, err := checkCompact(raw); err == nil {
			t.Fatal("accepted compact encoding")
		}
	}
}

func TestVerifierConcurrent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, jwks := testKey(t, "current")
	v := fixtureVerifier(t, jwks, now.Add(-10*time.Second))
	raw := signedClaims(t, key, testClaims(now))
	var wg sync.WaitGroup
	keys, _ := ParsePublicKeys(jwks)
	wg.Go(func() {
		for i := 1; i <= 100; i++ {
			if err := v.ReplaceKeys(keys, now.Add(-10*time.Second+time.Duration(i)*time.Millisecond)); err != nil {
				t.Error(err)
			}
		}
	})
	for range 16 {
		wg.Go(func() {
			for range 10 {
				if _, err := v.VerifySignature(t.Context(), raw, now); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func FuzzVerifier(f *testing.F) {
	now := time.Unix(1792230000, 0)
	key, jwks := testKey(f, "current")
	v := fixtureVerifier(f, jwks, now)
	f.Add(signedClaims(f, key, testClaims(now)))
	f.Add("e30.e30.AA")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = v.VerifySignature(t.Context(), raw, now) })
}
