package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func signingFixture(t *testing.T) (*Signer, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	public, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "current", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := authjwt.ParsePublicKeys(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := New("https://auth.example", "current", private, keys)
	if err != nil {
		t.Fatal(err)
	}
	return signer, private, public
}

func signingClaims(now time.Time) authjwt.Claims {
	return authjwt.Claims{
		Subject: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222", Audience: "orders",
		ExpiresAt: now.Add(2 * time.Minute).Unix(), AuthVersion: 1, Scope: "orders.read", Mode: authjwt.Strict, AuthTime: now.Add(-time.Minute).Unix(), Methods: []string{"pwd"},
	}
}

func TestSignAndVerify(t *testing.T) {
	signer, private, public := signingFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	keys, _ := authjwt.ParsePublicKeys(public)
	verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, now)
	if err != nil {
		t.Fatal(err)
	}
	input := signingClaims(now)
	input.Issuer = "https://forged.example"
	input.ID = "chosen-id"
	input.IssuedAt = 1
	first, err := signer.Sign(t.Context(), input, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.VerifySignature(t.Context(), first.Raw, now)
	if err != nil || got.Issuer != "https://auth.example" || got.IssuedAt != now.Unix() || got.ID == "chosen-id" || got.AuthTime != input.AuthTime || got.MFATime != nil {
		t.Fatal(got, err)
	}
	if first.ID != got.ID || first.ExpiresAt.Unix() != got.ExpiresAt {
		t.Fatal("audit metadata not bound to signed token")
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), first.Raw) {
		t.Fatal("raw token serialized into metadata", err)
	}
	second, err := signer.Sign(t.Context(), input, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := verifier.VerifySignature(t.Context(), second.Raw, now)
	if err != nil || next.ID == got.ID {
		t.Fatal("jti reused", err)
	}
	for _, bad := range []string{"https://forged.example", "PRIVATE KEY", string(private)} {
		if strings.Contains(first.Raw, bad) || strings.Contains(string(signer.PublicJWKS()), bad) {
			t.Fatal("secret/forged issuer leaked")
		}
	}
	input.Methods = []string{"pwd", "otp"}
	mfa := now.Add(-30 * time.Second).Unix()
	input.MFATime = &mfa
	raw, err := signer.Sign(t.Context(), input, now)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := verifier.VerifySignature(t.Context(), raw.Raw, now); err != nil || c.MFATime == nil || *c.MFATime != mfa {
		t.Fatal("MFA proof changed", err)
	}
	input.ExpiresAt = now.Add(6 * time.Minute).Unix()
	if _, err := signer.Sign(t.Context(), input, now); !errors.Is(err, authjwt.ErrInvalidToken) {
		t.Fatal("long-lived access", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := signer.Sign(ctx, signingClaims(now), now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for range cap(signer.admission) {
		signer.admission <- struct{}{}
	}
	if _, err := signer.Sign(t.Context(), signingClaims(now), now); !errors.Is(err, authjwt.ErrBusy) {
		t.Fatal("unbounded signing", err)
	}
}

func TestLoadKeys(t *testing.T) {
	_, private, public := signingFixture(t)
	dir := t.TempDir()
	privatePath, publicPath := filepath.Join(dir, "private.pem"), filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, public, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := KeyConfig{Enabled: true, Issuer: "https://auth.example", SigningKeyID: "current", PrivateKeyFile: privatePath, KeySetFile: publicPath}
	if _, err := Load(cfg); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(KeyConfig{PrivateKeyFile: "/not-readable", Issuer: "invalid"}); err != nil || s != nil {
		t.Fatal("disabled loaded keys", err)
	}
	cfg.SigningKeyID = "missing"
	if _, err := Load(cfg); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("key mismatch", err)
	}
	cfg.SigningKeyID = "current"
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfg); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("world-readable private key", err)
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte("not a key"), append([]byte("ignored preamble\n"), private...), append(append([]byte{}, private...), private...), []byte(strings.Repeat("x", 16*1024+1))} {
		if err := os.WriteFile(privatePath, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(cfg); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("invalid private key loaded", err)
		}
	}
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.KeySetFile = dir
	if _, err := Load(cfg); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("directory accepted", err)
	}
}

func TestSignerConcurrent(t *testing.T) {
	signer, _, _ := signingFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				if _, err := signer.Sign(t.Context(), signingClaims(now), now); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestRejectedSigningMaterial(t *testing.T) {
	_, private, public := signingFixture(t)
	keys, _ := authjwt.ParsePublicKeys(public)
	_, otherPrivate, _ := signingFixture(t)
	if _, err := New("https://auth.example", "current", otherPrivate, keys); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("mismatched private key", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := New("https://auth.example", "current", wrongCurve, keys); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("wrong signing curve", err)
	}
	for _, issuer := range []string{"", "http://auth.example", "https://auth.example?"} {
		if _, err := New(issuer, "current", private, keys); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("invalid issuer", err)
		}
	}
}
