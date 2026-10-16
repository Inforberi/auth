package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func checkMFAHTTPLogin(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("public", func(t *testing.T) { checkMFAHTTPFlow(t, db, ctx, false) })
	t.Run("administrative", func(t *testing.T) { checkMFAHTTPFlow(t, db, ctx, true) })
}

func checkMFAHTTPFlow(t *testing.T, db *pgxpool.Pool, ctx context.Context, administrative bool) {
	name, loginPath := "http-login", "/auth/login/email"
	if administrative {
		name, loginPath = "http-admin-login", "/admin/auth/login/email"
	}
	f := newMFALoginFixture(t, db, ctx, name)
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	encoded, err := hash.GenerateHash(ctx, []byte("Password12345"))
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1`, f.user, encoded)
	sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour})
	password := passwordservice.New(f.passwords, sessionservice.NewLogin(sessions, f.login), hash, loginTestLimit{})
	routes := router.New(router.Handlers{
		PasswordHandler: passwordhttp.New(password, zap.NewNop()),
		MFA:             mfahttp.New(mfaManagement(t, db), f.login, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()),
		Config: &config.Config{MFA: mfaservice.Config{Enabled: true}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}},
	})
	send := func(path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://localhost:8443/api/v1"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		routes.ServeHTTP(w, r)
		return w
	}
	if administrative {
		if denied := send(loginPath, `{"email":"`+f.email+`","password":"Password12345"}`, nil); denied.Code != 400 {
			t.Fatal("ordinary user accepted", denied.Code)
		}
		var role string
		if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES('http_admin','HTTP administrator') RETURNING id`).Scan(&role); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
			accessExec(t, db, ctx, `DELETE FROM auth.roles WHERE id=$1`, role)
		})
		accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'accounts.users.read')`, role)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, f.user, role)
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
	}
	login := send(loginPath, `{"email":"`+f.email+`","password":"Password12345"}`, nil)
	if login.Code != 202 {
		t.Fatal("primary login failed", login.Code, login.Body.String())
	}
	var challenge mfahttp.ChallengeResponse
	if err := json.Unmarshal(login.Body.Bytes(), &challenge); err != nil || challenge.Status != "mfa_required" {
		t.Fatal(err)
	}
	var binding *http.Cookie
	for _, cookie := range login.Result().Cookies() {
		if cookie.Name == mfahttp.LoginCookie {
			binding = cookie
		} else if cookie.Name == sessionhttp.SessionCookieName && cookie.MaxAge >= 0 {
			t.Fatal("primary login issued ordinary session")
		}
	}
	if binding == nil {
		t.Fatal("MFA browser binding absent")
	}
	body := `{"challenge":"` + challenge.Challenge + `","code":"` + f.codes[0] + `","recovery":true}`
	if failed := send("/auth/mfa/login/complete", body, nil); failed.Code != 400 {
		t.Fatal("foreign browser accepted", failed.Code)
	}
	complete := send("/auth/mfa/login/complete", body, binding)
	if complete.Code != 200 || complete.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(complete.Code, complete.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range complete.Result().Cookies() {
		if cookie.Name == sessionhttp.SessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("MFA completion did not issue session")
	}
	validation, err := sessions.ValidateSessionWithoutRefresh(ctx, sessionCookie.Value)
	if err != nil || validation.UserID != f.user || validation.MFAVerifiedAt == nil || validation.AuthVersion != 2 {
		t.Fatal("MFA session context", err)
	}
	if replay := send("/auth/mfa/login/complete", body, binding); replay.Code != 400 || len(replay.Result().Cookies()) != 0 {
		t.Fatal("replayed browser challenge issued session", replay.Code)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.user).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate browser sessions", count, err)
	}
	if err := mfapostgres.New(db).CheckDisabled(ctx); err == nil {
		t.Fatal("operational MFA bypass")
	}
}
