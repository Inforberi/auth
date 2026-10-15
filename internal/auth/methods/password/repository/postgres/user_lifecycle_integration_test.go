package postgres

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestUserLifecycleSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_lifecycle_runtime LOGIN PASSWORD 'synthetic-lifecycle-runtime';
		GRANT USAGE ON SCHEMA auth TO auth_lifecycle_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_lifecycle_runtime`)
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down"); accessExec(t, db, ctx, `DROP ROLE auth_lifecycle_runtime`) })
	cfg := db.Config()
	cfg.ConnConfig.User = "auth_lifecycle_runtime"
	cfg.ConnConfig.Password = "synthetic-lifecycle-runtime"
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('lifecycle_manager','Lifecycle manager') RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,unnest(ARRAY['accounts.users.status.manage','accounts.users.delete']) FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID)
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	actor.TokenHash = tokens.Hash(raw)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2,primary_verified_at=clock_timestamp()-interval '10 minutes' WHERE user_id=$1`, actor.UserID, actor.TokenHash)
	lifecycle := accountservice.NewUserLifecycle(accountpostgres.New(runtime))
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(runtime), tokens, sessionservice.Config{SessionTTL: 2 * time.Hour, SessionRefreshThreshold: 2 * time.Hour, AbsoluteSessionTTL: 24 * time.Hour})
	h := router.New(router.Handlers{UserLifecycle: accounthttp.NewUserLifecycle(lifecycle, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()), Config: &config.Config{MFA: mfaservice.Config{Enabled: true}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}}})
	send := func(method string, id accountdomain.UserID, body string) *httptest.ResponseRecorder {
		path := "https://localhost:8443/api/v1/admin/users/" + string(id)
		if method == "POST" {
			path += "/status"
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", "https://localhost:8443")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: raw})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if w.Code != status || code != "" && !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
			t.Fatal(w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("response renewed session or is cacheable", w.Header())
		}
	}
	blocked := `{"status":"blocked","expectedAuthVersion":1}`
	target := accessPrincipal(t, db, ctx)
	for _, permission := range []string{"accounts.users.read", "accounts.users.manage"} {
		accessExec(t, db, ctx, `UPDATE auth.role_permissions SET permission_key=$1 WHERE role_id=(SELECT role_id FROM auth.user_roles WHERE user_id=$2) AND permission_key='accounts.users.status.manage'`, permission, actor.UserID)
		check(send("POST", target.UserID, blocked), 403, "forbidden")
		accessExec(t, db, ctx, `UPDATE auth.role_permissions SET permission_key='accounts.users.status.manage' WHERE role_id=(SELECT role_id FROM auth.user_roles WHERE user_id=$1) AND permission_key=$2`, actor.UserID, permission)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id=(SELECT role_id FROM auth.user_roles WHERE user_id=$1) AND permission_key='accounts.users.delete'`, actor.UserID)
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":1}`), 403, "forbidden")
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT role_id,'accounts.users.delete' FROM auth.user_roles WHERE user_id=$1`, actor.UserID)
	check(send("POST", target.UserID, blocked), 200, "")
	check(send("POST", target.UserID, blocked), 409, "account_conflict")
	check(send("POST", target.UserID, `{"status":"blocked","expectedAuthVersion":2}`), 200, "")
	check(send("POST", target.UserID, `{"status":"active","expectedAuthVersion":2}`), 200, "")
	var live int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL`, target.UserID).Scan(&live); err != nil || live != 0 {
		t.Fatal("unblock revived sessions", live, err)
	}
	for _, column := range []string{"password_verified_at", "mfa_verified_at"} {
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+column+`=clock_timestamp()-interval '6 minutes' WHERE user_id=$1`, actor.UserID)
		check(send("DELETE", target.UserID, `{"expectedAuthVersion":3}`), 403, "fresh_auth_required")
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+column+`=clock_timestamp() WHERE user_id=$1`, actor.UserID)
	}
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":3}`), 200, "")
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":3}`), 409, "account_conflict")
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":4}`), 200, "")
	accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id=(SELECT role_id FROM auth.user_roles WHERE user_id=$1) AND permission_key='accounts.users.delete'`, actor.UserID)
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":4}`), 403, "forbidden")
	check(send("DELETE", "22222222-2222-4222-8222-222222222222", `{"expectedAuthVersion":1}`), 403, "forbidden")
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT role_id,'accounts.users.delete' FROM auth.user_roles WHERE user_id=$1`, actor.UserID)
	check(send("POST", target.UserID, `{"status":"active","expectedAuthVersion":4}`), 409, "account_deleted")
	check(send("DELETE", "22222222-2222-4222-8222-222222222222", `{"expectedAuthVersion":1}`), 404, "user_not_found")
	check(send("POST", "invalid", blocked), 400, "invalid_status_change")
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":0}`), 400, "invalid_deletion")
	var statusAudits, deletionAudits int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.account_status_audit WHERE user_id=$1 AND actor_id=$2),(SELECT count(*) FROM auth.account_deletion_audit WHERE user_id=$1 AND actor_id=$2)`, target.UserID, actor.UserID).Scan(&statusAudits, &deletionAudits); err != nil || statusAudits != 2 || deletionAudits != 1 {
		t.Fatal("audit/no-op attribution", statusAudits, deletionAudits, err)
	}
	checkLifecycleAdministratorRaces(t, db, ctx, lifecycle, actor)
	checkLifecycleRollback(t, db, ctx, lifecycle, actor)
	checkLifecycleRevocationWait(t, db, ctx, lifecycle, actor)
	// A revoked session cannot replay a committed deletion either.
	check(send("DELETE", target.UserID, `{"expectedAuthVersion":4}`), 401, "unauthorized")
}

func checkLifecycleAdministratorRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context, lifecycle *accountservice.UserLifecycle, actor accessservice.Principal) {
	t.Helper()
	var role string
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, actions := range [][2]string{{"block", "block"}, {"delete", "delete"}, {"block", "delete"}} {
		first, second := accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$3),($2,$3)`, first.UserID, second.UserID, role)
		remove := func(target accountdomain.UserID, action string) error {
			if action == "block" {
				_, err := lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: target, ExpectedVersion: 1, Status: accountdomain.StatusBlocked})
				return err
			}
			_, err := lifecycle.Delete(ctx, actor, accountdomain.AccountDeletion{UserID: target, ExpectedVersion: 1})
			return err
		}
		a, b := protectionPair(func() error { return remove(first.UserID, actions[0]) }, func() error { return remove(second.UserID, actions[1]) })
		firstWon := a == nil && errors.Is(b, accountdomain.ErrLastAdministrator)
		secondWon := b == nil && errors.Is(a, accountdomain.ErrLastAdministrator)
		if !firstWon && !secondWon {
			t.Fatal("lost last administrator", actions, a, b)
		}
		var remaining int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_roles ur JOIN auth.users u ON u.id=ur.user_id WHERE ur.role_id=$1 AND u.status='active' AND u.deleted_at IS NULL`, role).Scan(&remaining); err != nil || remaining != 1 {
			t.Fatal(remaining, err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
	}
}

func checkLifecycleRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, lifecycle *accountservice.UserLifecycle, actor accessservice.Principal) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$`)
	for _, table := range []string{"account_status_audit", "account_deletion_audit"} {
		target := accessPrincipal(t, db, ctx)
		accessExec(t, db, ctx, `CREATE TRIGGER reject_lifecycle_audit BEFORE INSERT ON auth.`+table+` FOR EACH ROW EXECUTE FUNCTION auth.reject_lifecycle_audit()`)
		var err error
		if table == "account_status_audit" {
			_, err = lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: target.UserID, ExpectedVersion: 1, Status: accountdomain.StatusBlocked})
		} else {
			_, err = lifecycle.Delete(ctx, actor, accountdomain.AccountDeletion{UserID: target.UserID, ExpectedVersion: 1})
		}
		if err == nil {
			t.Fatal("audit failure committed")
		}
		var intact bool
		if err := db.QueryRow(ctx, `SELECT u.status='active' AND u.auth_version=1 AND u.deleted_at IS NULL
			AND EXISTS(SELECT 1 FROM auth.sessions s WHERE s.user_id=u.id AND s.revoked_at IS NULL)
			AND EXISTS(SELECT 1 FROM auth.mfa_totp m WHERE m.user_id=u.id) FROM auth.users u WHERE id=$1`, target.UserID).Scan(&intact); err != nil || !intact {
			t.Fatal("partial lifecycle commit", err)
		}
		accessExec(t, db, ctx, `DROP TRIGGER reject_lifecycle_audit ON auth.`+table)
	}
	accessExec(t, db, ctx, `DROP FUNCTION auth.reject_lifecycle_audit()`)
	var pending accountdomain.UserID
	if err := db.QueryRow(ctx, `INSERT INTO auth.users(status) VALUES('pending') RETURNING id`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.account_provisions(user_id,actor_id,request_key,fingerprint) VALUES($1,$2,$1,repeat('a',64))`, pending, actor.UserID)
	if _, err := lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: pending, ExpectedVersion: 1, Status: accountdomain.StatusActive}); !errors.Is(err, accountdomain.ErrAccountConflict) {
		t.Fatal("pending activation bypass", err)
	}
	if _, err := lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: pending, ExpectedVersion: 1, Status: accountdomain.StatusBlocked}); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: pending, ExpectedVersion: 2, Status: accountdomain.StatusActive}); !errors.Is(err, accountdomain.ErrAccountConflict) {
		t.Fatal("blocked pending activation bypass", err)
	}
}

func checkLifecycleRevocationWait(t *testing.T, db *pgxpool.Pool, ctx context.Context, lifecycle *accountservice.UserLifecycle, actor accessservice.Principal) {
	t.Helper()
	for _, kind := range []string{"permission", "proof", "auth_version", "session"} {
		target := accessPrincipal(t, db, ctx)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Preserve the assertion failure; commit already closes the transaction.
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			t.Fatal(err)
		}
		query := map[string]string{
			"permission":   `DELETE FROM auth.user_roles WHERE user_id=$1`,
			"proof":        `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE user_id=$1`,
			"auth_version": `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
			"session":      `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`,
		}[kind]
		if _, err := tx.Exec(ctx, query, actor.UserID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := lifecycle.Delete(ctx, actor, accountdomain.AccountDeletion{UserID: target.UserID, ExpectedVersion: 1})
			result <- err
		}()
		poll := time.NewTicker(10 * time.Millisecond)
		until := time.Now().Add(2 * time.Second)
		waiting := false
		for time.Now().Before(until) {
			if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_lifecycle_runtime' AND wait_event='advisory')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-poll.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		poll.Stop()
		if !waiting {
			t.Fatal("mutation did not wait behind Access lock", kind)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			want := accessdomain.ErrFreshAuthRequired
			if kind == "permission" {
				want = accessdomain.ErrForbidden
			}
			if !errors.Is(err, want) {
				t.Fatal("stale authority used", kind, err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		var deleted bool
		if err := db.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM auth.users WHERE id=$1`, target.UserID).Scan(&deleted); err != nil || deleted {
			t.Fatal("unauthorized mutation committed", kind, err)
		}
		if kind != "session" {
			accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='lifecycle_manager' ON CONFLICT DO NOTHING`, actor.UserID)
			accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=1 WHERE id=$1`, actor.UserID)
			accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE user_id=$1`, actor.UserID)
		}
	}
}
