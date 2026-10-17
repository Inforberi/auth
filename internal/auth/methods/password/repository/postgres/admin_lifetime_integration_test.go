package postgres

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestAdministrativeSessionLifetime(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_as5_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_as5_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_as5_runtime`)
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down"); accessExec(t, db, ctx, `DROP ROLE auth_as5_runtime`) })
	runtime := operatorPool(t, ctx, db, "auth_as5_runtime")
	f := newStatusFixture(t, db, ctx, "as5-admin")
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('as5_admin','Admin') RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'accounts.users.read' FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	p := f.params
	p.TokenHash = tokens.Hash(raw)
	p.CreatedAt = time.Now().UTC()
	p.ExpiresAt, p.AbsoluteExpiresAt = p.CreatedAt.Add(168*time.Hour), p.CreatedAt.Add(336*time.Hour)
	p.AdminIdleTimeout, p.AdminAbsoluteTTL, p.AdminActivityInterval = 20*time.Minute, 8*time.Hour, 30*time.Second
	repo := sessionpostgres.New(runtime)
	expires, err := repo.CreateSession(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	session, err := repo.FindSession(ctx, p.TokenHash)
	if err != nil || !session.ExpiresAt.Equal(expires) || session.IdleTimeoutSeconds != 1200 ||
		expires.After(p.CreatedAt.Add(20*time.Minute)) || session.AbsoluteExpiresAt.After(p.CreatedAt.Add(8*time.Hour)) {
		t.Fatal("public login bypassed admin lifetime", session, expires, err)
	}
	// A generic refresh cannot bypass the explicit activity protocol, even through the repository.
	expected := session.ExpiresAt
	session.ExpiresAt = p.ExpiresAt
	if extended, err := repo.RefreshSession(ctx, p.TokenHash, session, expected); err != nil || extended || !session.ExpiresAt.Equal(expected) {
		t.Fatal("generic refresh extended admin session", extended, err)
	}
	if result, err := repo.RecordActivity(ctx, f.user, p.TokenHash); err != nil || result.Extended {
		t.Fatal("immediate activity wrote the ledger", result, err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET expires_at=statement_timestamp()+interval '17 minutes',
		password_verified_at=primary_verified_at,mfa_verified_at=primary_verified_at WHERE token_hash=$1`, p.TokenHash)
	var beforePrimary, beforePassword, beforeMFA time.Time
	if err := db.QueryRow(ctx, `SELECT primary_verified_at,password_verified_at,mfa_verified_at FROM auth.sessions WHERE token_hash=$1`, p.TokenHash).
		Scan(&beforePrimary, &beforePassword, &beforeMFA); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *sessionservice.ActivityResult, 16)
	failures := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			result, err := repo.RecordActivity(ctx, f.user, p.TokenHash)
			results <- result
			failures <- err
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	for result := range results {
		if result.Extended {
			writes++
		}
	}
	if writes != 1 {
		t.Fatal("concurrent activity was not coalesced", writes)
	}
	var unchanged bool
	if err := db.QueryRow(ctx, `SELECT primary_verified_at=$2 AND password_verified_at=$3 AND mfa_verified_at=$4
		AND absolute_expires_at=$5 FROM auth.sessions WHERE token_hash=$1`, p.TokenHash, beforePrimary, beforePassword, beforeMFA, session.AbsoluteExpiresAt).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("activity renewed proof/absolute deadline", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.sessions SET idle_timeout_seconds=1800 WHERE token_hash=$1`, p.TokenHash); err == nil {
		t.Fatal("stored lifetime policy was mutable")
	}
	// Once clamped to absolute expiry, further activity is a no-op.
	accessExec(t, db, ctx, `UPDATE auth.sessions SET absolute_expires_at=statement_timestamp()+interval '5 minutes',
		expires_at=statement_timestamp()+interval '2 minutes' WHERE token_hash=$1`, p.TokenHash)
	result, err := repo.RecordActivity(ctx, f.user, p.TokenHash)
	if err != nil || !result.Extended {
		t.Fatal("activity did not clamp", result, err)
	}
	clamped, err := repo.FindSession(ctx, p.TokenHash)
	if err != nil || !clamped.ExpiresAt.Equal(clamped.AbsoluteExpiresAt) {
		t.Fatal("absolute clamp failed", clamped, err)
	}
	if next, err := repo.RecordActivity(ctx, f.user, p.TokenHash); err != nil || next.Extended {
		t.Fatal("absolute boundary wrote again", next, err)
	}

	cfg := &config.Config{}
	cfg.Browser.AllowedOrigins = []string{"https://auth.example.com"}
	middleware := sessionhttp.New(sessionservice.New(clock.UTCClock{}, repo, tokens, sessionservice.Config{
		SessionTTL: 168 * time.Hour, AbsoluteSessionTTL: 336 * time.Hour, SessionRefreshThreshold: 24 * time.Hour,
	}), zap.NewNop())
	routes := router.New(router.Handlers{
		Config: cfg, Logger: zap.NewNop(), Middleware: middleware,
		Session:  sessionhttp.NewHandler(sessionservice.NewManagement(repo), zap.NewNop()),
		Activity: sessionhttp.NewActivity(sessionservice.NewActivity(repo), zap.NewNop()),
	})
	request := func(origin, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/api/v1/auth/session/activity", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: cookie})
		}
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}
	if w := request("https://evil.example", raw); w.Code != 403 {
		t.Fatal("activity missing Origin guard", w.Code)
	}
	if w := request("https://auth.example.com", ""); w.Code != 401 {
		t.Fatal("anonymous activity accepted", w.Code)
	}
	if w := request("https://auth.example.com", raw); w.Code != 200 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-op activity HTTP contract failed", w.Code, w.Body.String())
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET expires_at=statement_timestamp()+interval '2 minutes' WHERE token_hash=$1`, p.TokenHash)
	if w := request("https://auth.example.com", raw); w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Value != raw {
		t.Fatal("activity did not return the same secure cookie after extension", w.Code, w.Header())
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET created_at=statement_timestamp()-interval '2 hours',
		expires_at=statement_timestamp() WHERE token_hash=$1`, p.TokenHash)
	if _, err := repo.RecordActivity(ctx, f.user, p.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("expired session revived", err)
	}
	if w := request("https://auth.example.com", raw); w.Code != 401 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("expired activity renewed cookie", w.Code)
	}
	if allowed, err := accesspostgres.New(runtime).HasPermission(ctx, accessservice.Principal{UserID: f.user, TokenHash: p.TokenHash}, accessdomain.PermissionKey("accounts.users.read")); err != nil || allowed {
		t.Fatal("direct Access ignored idle expiry", allowed, err)
	}
	if _, err := repo.RotateSession(ctx, f.user, p.TokenHash, tokens.Hash("replacement")); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("rotation revived expiry", err)
	}
	if _, err := repo.ConfirmPassword(ctx, f.user, p.TokenHash, "old-hash", p.AuthVersion, tokens.Hash("reauth")); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("reauth revived expiry", err)
	}
}

func TestAdministrativeMFALifetime(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('as5_mfa','Admin') RETURNING id)
		INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'accounts.users.read' FROM r`)
	for _, administrative := range []bool{false, true} {
		name := "public"
		if administrative {
			name = "private"
		}
		t.Run(name, func(t *testing.T) {
			f := newMFALoginFixture(t, db, ctx, "as5-"+name)
			accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='as5_mfa'`, f.user)
			accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
			cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
			if err != nil {
				t.Fatal(err)
			}
			f.proof.Administrative = administrative
			f.login, err = mfaservice.NewLogin(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{
				ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
				AdminIdleTimeout: 20 * time.Minute, AdminAbsoluteTTL: 8 * time.Hour, AdminActivityInterval: 30 * time.Second,
				UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.login.Complete(ctx, f.start(t, ctx))
			if err != nil {
				t.Fatal(err)
			}
			stored, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(result.Token))
			if err != nil || stored.IdleTimeoutSeconds != 1200 || !result.ExpiresAt.Equal(stored.ExpiresAt) ||
				stored.ExpiresAt.Sub(stored.CreatedAt) != 20*time.Minute || stored.AbsoluteExpiresAt.Sub(stored.CreatedAt) != 8*time.Hour {
				t.Fatal("MFA completion lost the independent configured admin profile", stored, err)
			}
		})
	}
}
