package auth

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	oidcdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	oidcredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/repository/redis"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	mfaredis "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/redis"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func realmRedisFixture(t *testing.T) (*redis.Client, context.Context) {
	t.Helper()
	addr := os.Getenv("AUTH_REALM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("requires explicit disposable loopback Redis DB15")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("refusing non-loopback Redis fixture")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_REALM_TEST_REDIS_PASSWORD"), DB: 15, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	if size, err := client.DBSize(ctx).Result(); err != nil || size != 0 {
		t.Fatal("explicit fixture DB15 must be empty", err)
	}
	return client, ctx
}

func TestRealmRedisIsolation(t *testing.T) {
	client, ctx := realmRedisFixture(t)
	id := "1c82c477-3a57-4823-8c49-a476550d8a21"
	realms := []realmSecurity{testRealmSecurity(t, "platform", id), testRealmSecurity(t, "project", id), testRealmSecurity(t, "project", "2c82c477-3a57-4823-8c49-a476550d8a21")}
	var keys []string
	track := func(scope realmscope.Scope, purpose, legacy string, suffixes ...string) string {
		prefix, err := scope.RedisPrefix(purpose, legacy)
		if err != nil {
			t.Fatal(err)
		}
		for _, suffix := range suffixes {
			keys = append(keys, prefix+suffix)
		}
		return prefix
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if len(keys) > 0 {
			if err := client.Del(cleanup, keys...).Err(); err != nil {
				t.Error("fixture key cleanup failed", err)
			}
		}
		if size, err := client.DBSize(cleanup).Result(); err != nil || size != 0 {
			t.Error("scoped adapters leaked unexpected keys", size, err)
		}
	})
	for _, realm := range realms {
		account, err := accountredis.NewScoped(client, realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		password, err := passwordredis.NewScoped(client, realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		mfa, err := mfaredis.NewScoped(client, realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		smtp, err := settingsredis.NewSMTPScoped(client, realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			purpose string
			allow   func(context.Context, string, int, time.Duration) (bool, error)
		}{
			{"email-verification-limit", account.Allow}, {"password-limit", password.Allow}, {"mfa-limit", mfa.Allow}, {"smtp-test-limit", smtp.Allow},
		} {
			prefix := track(realm.scope, test.purpose, "unused", "identical-key")
			for i := range 2 {
				allowed, err := test.allow(ctx, "identical-key", 1, time.Minute)
				if err != nil || allowed != (i == 0) {
					t.Fatal("realm budget collision", test.purpose, err)
				}
			}
			if ttl, err := client.PTTL(ctx, prefix+"identical-key").Result(); err != nil || ttl <= 0 || ttl > time.Minute {
				t.Fatal("unbounded scoped counter", ttl, err)
			}
		}
		track(realm.scope, "mfa-limit", "unused", "parallel-user", "parallel-project")
		var accepted atomic.Int32
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				allowed, err := mfa.AllowAll(ctx, []mfaservice.Budget{{Key: "parallel-user", Count: 3}, {Key: "parallel-project", Count: 3}})
				if err != nil {
					t.Error(err)
				} else if allowed {
					accepted.Add(1)
				}
			})
		}
		wg.Wait()
		if accepted.Load() != 3 {
			t.Fatal("non-atomic scoped MFA admission", accepted.Load())
		}
		// Identical digester isolates the key-prefix guarantee from crypto-domain separation.
		cipher, err := (realmSecurity{scope: realmscope.Legacy()}).cipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "jwt-issuance-limits:v1")
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := tokenredis.NewScoped(client, cipher, tokenredis.Limits{ActorPerMinute: 1, SessionPerMinute: 1, IPPerMinute: 1, ProjectPerMinute: 1}, realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		track(realm.scope, "jwt-issuance", "unused", "actor:"+cipher.Digest(""), "session:"+cipher.Digest("same-session"), "ip:"+cipher.Digest("192.0.2.1"), "project")
		input := tokenservice.ExchangeInput{SessionID: "same-session", IP: "192.0.2.1"}
		if err := jwt.Allow(ctx, input); err != nil {
			t.Fatal("realm JWT budget collided", err)
		}
		if err := jwt.AllowNative(ctx, "", input.IP); !errors.Is(err, tokendomain.ErrRateLimited) {
			t.Fatal("native issuance bypassed shared JWT budget", err)
		}
		track(realm.scope, "jwt-refresh-lookup", "unused", "ip:"+cipher.Digest(input.IP), "project")
		if err := jwt.AllowCredentialLookup(ctx, input.IP); err != nil {
			t.Fatal(err)
		}
		if err := jwt.AllowCredentialLookup(ctx, input.IP); !errors.Is(err, tokendomain.ErrRateLimited) {
			t.Fatal(err)
		}
		track(realm.scope, "jwt-introspection", "unused", "client:"+cipher.Digest("same-client"), "project")
		if err := jwt.AllowIntrospection(ctx, "same-client", 1, 1); err != nil {
			t.Fatal(err)
		}
		if err := jwt.AllowIntrospection(ctx, "same-client", 1, 1); !errors.Is(err, tokendomain.ErrRateLimited) {
			t.Fatal(err)
		}
	}
	t.Run("OIDC", func(t *testing.T) { scopedOIDC(t, client, ctx, realms, track) })
	t.Run("legacy keys", func(t *testing.T) {
		for _, test := range []struct {
			oldPrefix string
			allow     func(context.Context, string, int, time.Duration) (bool, error)
		}{
			{"auth:email-verification:limit:", accountredis.New(client).Allow},
			{"auth:password-recovery:limit:", passwordredis.New(client).Allow},
			{"auth:mfa:limit:", mfaredis.New(client).Allow},
			{"auth:settings:smtp-test:", settingsredis.NewSMTP(client).Allow},
		} {
			track(realmscope.Legacy(), "fixture", test.oldPrefix, "legacy-fixture")
			if ok, err := test.allow(ctx, "legacy-fixture", 1, time.Minute); err != nil || !ok {
				t.Fatal(err)
			}
			if n, err := client.Get(ctx, test.oldPrefix+"legacy-fixture").Int(); err != nil || n != 1 {
				t.Fatal("legacy key changed", err)
			}
		}
	})
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	limiter, err := passwordredis.NewScoped(client, realms[0].scope)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := limiter.Allow(cancelled, "cancelled", 1, time.Minute); allowed || err == nil {
		t.Fatal("dependency cancellation admitted request")
	}
	for _, key := range keys {
		if strings.Contains(key, "unused") {
			t.Fatal("scoped adapter fell back to legacy")
		}
	}
	t.Run("legacy scoped constructors", func(t *testing.T) {
		account, err := accountredis.NewScoped(client, realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		password, err := passwordredis.NewScoped(client, realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		mfa, err := mfaredis.NewScoped(client, realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		smtp, err := settingsredis.NewSMTPScoped(client, realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		for _, allow := range []func(context.Context, string, int, time.Duration) (bool, error){account.Allow, password.Allow, mfa.Allow, smtp.Allow} {
			if allowed, err := allow(ctx, "legacy-fixture", 1, time.Minute); allowed || err != nil {
				t.Fatal("scoped legacy constructor changed existing bucket", err)
			}
			if allowed, err := allow(cancelled, "cancelled", 1, time.Minute); allowed || err == nil {
				t.Fatal("dependency failure admitted simple limiter", err)
			}
		}
		cipher, err := (realmSecurity{scope: realmscope.Legacy()}).cipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "jwt-issuance-limits:v1")
		if err != nil {
			t.Fatal(err)
		}
		jwt, err := tokenredis.NewScoped(client, cipher, tokenredis.Limits{ActorPerMinute: 1, SessionPerMinute: 1, IPPerMinute: 1, ProjectPerMinute: 1}, realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		track(realmscope.Legacy(), "fixture", "auth:{jwt-issuance}:", "actor:"+cipher.Digest(""), "session:"+cipher.Digest("legacy"), "ip:"+cipher.Digest("192.0.2.1"), "project")
		track(realmscope.Legacy(), "fixture", "auth:{jwt-refresh-lookup}:", "ip:"+cipher.Digest("192.0.2.1"), "project")
		track(realmscope.Legacy(), "fixture", "auth:{jwt-introspection}:", "client:"+cipher.Digest("legacy"), "project")
		if err := jwt.Allow(ctx, tokenservice.ExchangeInput{SessionID: "legacy", IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
		if err := jwt.AllowCredentialLookup(ctx, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		if err := jwt.AllowIntrospection(ctx, "legacy", 1, 1); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"auth:{jwt-issuance}:", "auth:{jwt-refresh-lookup}:", "auth:{jwt-introspection}:"} {
			if n, err := client.Get(ctx, prefix+"project").Int(); err != nil || n != 1 {
				t.Fatal("legacy JWT project budget changed", err)
			}
		}
		flow, err := oidcredis.NewScoped(client, cipher, "google", realmscope.Legacy())
		if err != nil {
			t.Fatal(err)
		}
		track(realmscope.Legacy(), "fixture", "auth:google:", "flow:"+cipher.Digest("legacy"))
		if err := flow.Save(ctx, "legacy", "browser", oidcdomain.Flow{Verifier: "legacy-verifier", Purpose: oidcdomain.Login}); err != nil {
			t.Fatal(err)
		}
		oldFlow := oidcredis.New(client, cipher, "auth:google")
		if result, err := oldFlow.Consume(ctx, "legacy", "browser"); err != nil || result.Verifier != "legacy-verifier" {
			t.Fatal("legacy OIDC key changed", err)
		}
	})
}

func scopedOIDC(t *testing.T, client *redis.Client, ctx context.Context, realms []realmSecurity, track func(realmscope.Scope, string, string, ...string) string) {
	t.Helper()
	cipher, err := (realmSecurity{scope: realmscope.Legacy()}).cipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "google-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	var repos []*oidcredis.Repository
	for _, realm := range realms {
		repo, err := oidcredis.NewScoped(client, cipher, "google", realm.scope)
		if err != nil {
			t.Fatal(err)
		}
		repos = append(repos, repo)
		track(realm.scope, "oidc-google", "auth:google:", "flow:"+cipher.Digest("same-state"))
	}
	for i, repo := range repos {
		track(realms[i].scope, "oidc-google", "unused", "limit:"+cipher.Digest("same-ip"), "limit:global")
		if allowed, err := repo.Allow(ctx, "same-ip", 1, 1); err != nil || !allowed {
			t.Fatal("OIDC global budget crossed realm", err)
		}
		if allowed, err := repo.Allow(ctx, "same-ip", 1, 1); err != nil || allowed {
			t.Fatal("OIDC budget was bypassed", err)
		}
		flow := oidcdomain.Flow{Verifier: "private-verifier", Nonce: "fixture-nonce", Purpose: oidcdomain.Login}
		if err := repo.Save(ctx, "same-state", "same-binding", flow); err != nil {
			t.Fatal(err)
		}
		prefix, err := realms[i].scope.RedisPrefix("oidc-google", "unused")
		if err != nil {
			t.Fatal(err)
		}
		key := prefix + "flow:" + cipher.Digest("same-state")
		if ttl, err := client.PTTL(ctx, key).Result(); err != nil || ttl <= 0 || ttl > 5*time.Minute {
			t.Fatal("flow TTL", ttl, err)
		}
		if payload, err := client.HGet(ctx, key, "payload").Result(); err != nil || strings.Contains(payload, flow.Verifier) {
			t.Fatal("plaintext OIDC payload", err)
		}
		for j, other := range repos {
			if i != j {
				if _, err := other.Consume(ctx, "same-state", "same-binding"); !errors.Is(err, oidcdomain.ErrInvalidFlow) {
					t.Fatal("flow crossed Redis realm namespace", err)
				}
			}
		}
		telegram, err := oidcredis.NewScoped(client, cipher, "telegram", realms[i].scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := telegram.Consume(ctx, "same-state", "same-binding"); !errors.Is(err, oidcdomain.ErrInvalidFlow) {
			t.Fatal("flow crossed provider namespace", err)
		}
		if _, err := repo.Consume(ctx, "same-state", "wrong-binding"); !errors.Is(err, oidcdomain.ErrInvalidFlow) {
			t.Fatal("wrong browser consumed flow", err)
		}
		var wg sync.WaitGroup
		var consumed atomic.Int32
		for range 12 {
			wg.Go(func() {
				result, err := repo.Consume(ctx, "same-state", "same-binding")
				if err == nil && result.Verifier == flow.Verifier {
					consumed.Add(1)
				} else if !errors.Is(err, oidcdomain.ErrInvalidFlow) {
					t.Error("unexpected consume result", err)
				}
			})
		}
		wg.Wait()
		if consumed.Load() != 1 {
			t.Fatal("non-atomic flow consumption", consumed.Load())
		}
	}
}
