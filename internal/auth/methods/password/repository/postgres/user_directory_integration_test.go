package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type directoryTrace struct {
	sql   string
	args  []any
	calls int
}

func (tr *directoryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "WITH directory_actor AS") {
		tr.sql = data.SQL
		tr.args = append([]any(nil), data.Args...)
		tr.calls++
	}
	return ctx
}

func (*directoryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestUserDirectorySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_directory_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_directory_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_directory_runtime`)
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down"); accessExec(t, db, ctx, `DROP ROLE auth_directory_runtime`) })
	trace := &directoryTrace{}
	cfg := db.Config()
	cfg.ConnConfig.User = "auth_directory_runtime"
	cfg.ConnConfig.Password = "synthetic-recovery-only"
	cfg.ConnConfig.Tracer = trace
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	reader, manager := accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx)
	for _, entry := range []struct {
		actor           accessservice.Principal
		key, permission string
	}{
		{reader, "directory_reader", "accounts.users.read"}, {manager, "directory_manager", "accounts.users.manage"},
	} {
		accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES($2,$2) RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$3 FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, entry.actor.UserID, entry.key, entry.permission)
	}
	tokens := tokengenerate.New()
	raw := func(actor accessservice.Principal) string {
		token, err := tokens.GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2,password_verified_at=NULL,mfa_verified_at=NULL WHERE user_id=$1`, actor.UserID, tokens.Hash(token))
		return token
	}
	readerRaw, managerRaw := raw(reader), raw(manager)
	reader.TokenHash = tokens.Hash(readerRaw)
	directory := accountservice.NewUserDirectory(accountpostgres.New(runtime))
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(runtime), tokens, sessionservice.Config{SessionTTL: 2 * time.Hour, SessionRefreshThreshold: 2 * time.Hour, AbsoluteSessionTTL: 24 * time.Hour})
	h := router.New(router.Handlers{UserDirectory: accounthttp.NewUserDirectory(directory, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()), Config: &config.Config{}})
	send := func(path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://localhost:8443/api/v1/admin/users"+path, nil)
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	check(send("", managerRaw), 403)
	check(send("/00000000-0000-4000-8000-000000000000", managerRaw), 403)
	check(send("/00000000-0000-4000-8000-000000000000", readerRaw), 404)
	check(send("/invalid", readerRaw), 400)
	target, err := New(db).CreateUser(ctx, "directory@example.com", "directory-private-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, target)
	accessExec(t, db, ctx, `UPDATE auth.user_profile SET display_name='Directory user' WHERE user_id=$1`, target)
	accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) VALUES('https://accounts.google.com','directory-private-subject',$1)`, target)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, target, []byte(strings.Repeat("private-factor", 4)))
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='directory_reader'`, target)
	response := send("/"+string(target), readerRaw)
	check(response, 200)
	var card accounthttp.UserDetailResponse
	if err := json.Unmarshal(response.Body.Bytes(), &card); err != nil || !card.PasswordConfigured || !card.MFAEnrolled || !card.EmailVerified || len(card.Contacts) != 1 || len(card.ExternalIssuers) != 1 || len(card.Roles) != 1 || card.AuthVersion != 1 {
		t.Fatal("user card", err, response.Body.String())
	}
	for _, secret := range []string{"directory-private-password-hash", "directory-private-subject", "private-factor", "tokenHash", "recoveryCodes", "secret"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("card leaked secret")
		}
	}
	response = send("?email="+url.QueryEscape(" DIRECTORY@example.com "), readerRaw)
	check(response, 200)
	var page accounthttp.UserPageResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Users) != 1 || page.Users[0].ID != target || page.NextCursor != "" {
		t.Fatal("exact email", err)
	}
	response = send("?email=unknown%40example.com", readerRaw)
	check(response, 200)
	if !strings.Contains(response.Body.String(), `"users":[]`) {
		t.Fatal("authorized empty page was denied")
	}
	pending := newInvitationFixture(t, db, ctx, "directory")
	ids := make([]string, 0, 3)
	for range 3 {
		input := pending.input
		input.Invite = false
		input.Email = ""
		input.IdempotencyKey = temporaryRequestKey(t, db, ctx)
		result, err := pending.provision.Provision(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, string(result.UserID))
		accessExec(t, db, ctx, `UPDATE auth.users SET created_at='2026-01-01T00:00:00Z' WHERE id=$1`, result.UserID)
	}
	slices.Sort(ids)
	slices.Reverse(ids)
	response = send("?status=pending&limit=2", readerRaw)
	check(response, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Users) != 2 || string(page.Users[0].ID) != ids[0] || string(page.Users[1].ID) != ids[1] || page.NextCursor == "" {
		t.Fatal("timestamp/UUID ordering", err, response.Body.String())
	}
	response = send("?status=pending&limit=2&before="+page.NextCursor, readerRaw)
	check(response, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Users) != 1 || string(page.Users[0].ID) != ids[2] || page.NextCursor != "" {
		t.Fatal("keyset skipped/duplicated a user", err, response.Body.String())
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, target)
	response = send("?email=directory%40example.com", readerRaw)
	check(response, 200)
	if !strings.Contains(response.Body.String(), `"users":[]`) {
		t.Fatal("list included deleted owner")
	}
	response = send("/"+string(target), readerRaw)
	check(response, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &card); err != nil || card.DeletedAt == nil || card.Status != "blocked" {
		t.Fatal("retained deletion card", err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id) SELECT 'https://directory-'||n||'.example','private-subject',$1 FROM generate_series(1,33) n`, target)
	check(send("/"+string(target), readerRaw), 409)
	accessExec(t, db, ctx, `DELETE FROM auth.linked_identities WHERE user_id=$1 AND issuer LIKE 'https://directory-%'`, target)
	accessExec(t, db, ctx, `INSERT INTO auth.user_emails(user_id,email) SELECT $1,'directory-extra-'||n||'@example.com' FROM generate_series(1,33) n`, target)
	check(send("/"+string(target), readerRaw), 409)
	accessExec(t, db, ctx, `DELETE FROM auth.user_emails WHERE user_id=$1 AND email::text LIKE 'directory-extra-%'`, target)
	accessExec(t, db, ctx, `WITH r AS (
		INSERT INTO auth.roles(key,name) SELECT 'directory_extra_'||n,'Extra role' FROM generate_series(1,33) n RETURNING id
	) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, target)
	check(send("/"+string(target), readerRaw), 409)
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN (SELECT id FROM auth.roles WHERE key LIKE 'directory_extra_%')`, target)
	checkUserDirectoryPlans(t, db, ctx, trace, func(path string) *httptest.ResponseRecorder { return send(path, readerRaw) })
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, reader.UserID)
	check(send("", readerRaw), 403)
	check(send("/"+string(target), readerRaw), 403)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='directory_reader'`, reader.UserID)
	accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, reader.UserID)
	check(send("", readerRaw), 401)
	if _, err := directory.Read(ctx, reader, target); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("direct read bypassed current auth_version", err)
	}
	accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=1 WHERE id=$1`, reader.UserID)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, reader.UserID)
	check(send("", readerRaw), 401)
}
