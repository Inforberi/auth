package auth

import (
	"encoding/base64"
	"testing"

	"github.com/redis/go-redis/v9"

	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func testRealmSecurity(t *testing.T, kind, id string) realmSecurity {
	t.Helper()
	scope, err := realmscope.New(kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return realmSecurity{scope: scope}
}

func TestZeroScopeRejectedByAdapters(t *testing.T) {
	client := &redis.Client{} // Constructors must reject scope before any network operation.
	scope := realmscope.Scope{}
	if _, err := accountredis.NewScoped(client, scope); err == nil {
		t.Fatal("account accepted missing realm")
	}
	if _, err := passwordredis.NewScoped(client, scope); err == nil {
		t.Fatal("password accepted missing realm")
	}
	if _, err := mfaredis.NewScoped(client, scope); err == nil {
		t.Fatal("MFA accepted missing realm")
	}
	if _, err := settingsredis.NewSMTPScoped(client, scope); err == nil {
		t.Fatal("SMTP accepted missing realm")
	}
	cipher, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokenredis.NewScoped(client, cipher, tokenredis.DefaultLimits(), scope); err == nil {
		t.Fatal("JWT accepted missing realm")
	}
	if _, err := oidcredis.NewScoped(client, cipher, "google", scope); err == nil {
		t.Fatal("OIDC accepted missing realm")
	}
}

func TestRealmEncryptionIsolation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	id := "1c82c477-3a57-4823-8c49-a476550d8a21"
	realms := []realmSecurity{
		{scope: realmscope.Legacy()},
		testRealmSecurity(t, "platform", id),
		testRealmSecurity(t, "project", id),
		testRealmSecurity(t, "project", "2c82c477-3a57-4823-8c49-a476550d8a21"),
	}
	for _, purpose := range []string{
		"email-verification:v1", "initial-setup:v1", "mfa:v1", "email-login:v1", "password-reset:v1",
		"smtp-settings:v1", "provider-google:v1", "provider-telegram:v1", "google-login:v1", "telegram-login:v1", "jwt-issuance-limits:v1",
	} {
		t.Run(purpose, func(t *testing.T) {
			var ciphers []*secretbox.Cipher
			seen := map[string]bool{}
			for _, realm := range realms {
				cipher, err := realm.cipher(key, purpose)
				if err != nil {
					t.Fatal(err)
				}
				digest := cipher.Digest("identical-user-token-ip")
				if seen[digest] {
					t.Fatal("digest crossed realm boundary")
				}
				seen[digest] = true
				ciphers = append(ciphers, cipher)
			}
			for i, source := range ciphers {
				payload, err := source.Seal([]byte("persistent-secret"))
				if err != nil {
					t.Fatal(err)
				}
				for j, target := range ciphers {
					plain, err := target.Open(payload)
					if i == j && (err != nil || string(plain) != "persistent-secret") || i != j && err == nil {
						t.Fatalf("unexpected cross-realm decrypt %d -> %d", i, j)
					}
				}
			}
			old, err := secretbox.NewScoped(key, purpose)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := old.Seal([]byte("legacy-payload"))
			if err != nil {
				t.Fatal(err)
			}
			if plain, err := ciphers[0].Open(payload); err != nil || string(plain) != "legacy-payload" || ciphers[0].Digest("sample") != old.Digest("sample") {
				t.Fatal("standalone legacy ciphertext/digest changed", err)
			}
		})
	}
	if _, err := (realmSecurity{}).cipher(key, "mfa:v1"); err == nil {
		t.Fatal("zero scope encrypted with legacy context")
	}
}
