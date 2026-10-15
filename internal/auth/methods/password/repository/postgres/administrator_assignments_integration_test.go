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
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
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

func TestAdministratorAssignmentsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_administrators_runtime LOGIN PASSWORD 'synthetic-administrators';
		GRANT USAGE ON SCHEMA auth TO auth_administrators_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_administrators_runtime`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `DROP ROLE auth_administrators_runtime`)
	})
	cfg := db.Config()
	cfg.ConnConfig.User = "auth_administrators_runtime"
	cfg.ConnConfig.Password = "synthetic-administrators"
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	catalog, err := settings.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := accessservice.New(accesspostgres.New(runtime), catalog)
	var role accessdomain.RoleID
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Super admin',true) RETURNING id`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(catalog.Permissions()))
	for _, p := range catalog.Permissions() {
		keys = append(keys, string(p.Key))
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[])`, role, keys)
	actor := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, actor.UserID)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, actor.UserID, role)
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	actor.TokenHash = tokens.Hash(raw)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE user_id=$1`, actor.UserID, actor.TokenHash)
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(runtime), tokens, sessionservice.Config{SessionTTL: 2 * time.Hour, SessionRefreshThreshold: 2 * time.Hour, AbsoluteSessionTTL: 24 * time.Hour})
	h := router.New(router.Handlers{Access: accesshttp.New(svc, zap.NewNop()), Middleware: sessionhttp.New(sessions, zap.NewNop()), Config: &config.Config{MFA: mfaservice.Config{Enabled: true}, Browser: requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}}}})
	send := func(method string, id accountdomain.UserID, version string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://localhost:8443/api/v1/admin/users/"+string(id)+"/administrator", strings.NewReader(`{"expectedAuthVersion":1,"expectedRoleVersion":1,"expectedAccessVersion":`+version+`}`))
		r.Header.Set("Origin", "https://localhost:8443")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: raw})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal(w.Code, w.Header(), w.Body.String())
		}
	}
	target := accessPrincipal(t, db, ctx)
	check(send("POST", actor.UserID, "1"), 403)
	check(send("POST", target.UserID, "1"), 409) // Enrolled MFA alone is not a permanent password login.
	prepareUsableAdministrator(t, db, ctx, target.UserID)
	for _, column := range []string{"password_verified_at", "mfa_verified_at"} {
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+column+`=NULL WHERE user_id=$1`, actor.UserID)
		check(send("POST", target.UserID, "1"), 403)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET `+column+`=clock_timestamp() WHERE user_id=$1`, actor.UserID)
	}
	check(send("POST", target.UserID, "1"), 200)
	check(send("POST", target.UserID, "1"), 409)
	check(send("POST", target.UserID, "2"), 200)
	if err := svc.Authorize(ctx, target, settings.AssignmentsManage); err != nil {
		t.Fatal("grant not effective", err)
	}
	check(send("DELETE", target.UserID, "2"), 200)
	check(send("DELETE", target.UserID, "3"), 200)
	if err := svc.Authorize(ctx, target, settings.AssignmentsManage); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("revoke not immediate", err)
	}
	var audits int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.access_audit WHERE target_id=$1 AND role_id=$2`, target.UserID, role).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("duplicate audit", audits, err)
	}
	ordinary := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('ordinary_admin','Ordinary admin') RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,unnest($2::text[]) FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, ordinary.UserID, keys)
	command := administratorCommand(ordinary, target.UserID, true)
	command.ExpectedAccessVersion = 3
	if _, err := svc.ChangeAdministrator(ctx, command); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("custom role promoted system admin", err)
	}
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role, ExpectedRoleVersion: 1, ExpectedAccessVersion: 3, Grant: true}); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("ordinary assignment changed system role", err)
	}
	command = administratorCommand(actor, target.UserID, true)
	command.ExpectedAccessVersion = 3
	for _, mutate := range []func(*accessservice.AdministratorInput){func(i *accessservice.AdministratorInput) { i.ExpectedAuthVersion = 2 }, func(i *accessservice.AdministratorInput) { i.ExpectedAccessVersion = 4 }, func(i *accessservice.AdministratorInput) { i.ExpectedRoleVersion = 2 }} {
		bad := command
		mutate(&bad)
		if _, err := svc.ChangeAdministrator(ctx, bad); !errors.Is(err, accessdomain.ErrConflict) {
			t.Fatal("stale version accepted", err)
		}
	}
	checkUnusableAdministratorBackups(t, db, ctx, svc, accountservice.NewUserLifecycle(accountpostgres.New(runtime)), actor, role)
	checkAdministratorAssignmentRollback(t, db, ctx, svc, actor, target.UserID, 3)
	checkAdministratorConcurrentGrant(t, db, ctx, svc, actor)
	checkAdministratorRemovalRaces(t, db, ctx, svc, accountservice.NewUserLifecycle(accountpostgres.New(runtime)), actor, role)
	checkAdministratorRevocationWait(t, db, ctx, svc, actor, role)
	// Promote a ready backup, then self-revoke. The former owner immediately loses this API.
	check(send("POST", target.UserID, "3"), 200)
	check(send("DELETE", actor.UserID, "1"), 200)
	check(send("POST", ordinary.UserID, "1"), 403)
	if _, err := svc.ChangeAdministrator(ctx, administratorCommand(target, target.UserID, false)); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatal("target version guard lost", err)
	}
	last := administratorCommand(target, target.UserID, false)
	last.ExpectedAccessVersion = 4
	if _, err := svc.ChangeAdministrator(ctx, last); !errors.Is(err, accountdomain.ErrLastAdministrator) {
		t.Fatal("last usable administrator removed", err)
	}
}

func administratorCommand(actor accessservice.Principal, target accountdomain.UserID, grant bool) accessservice.AdministratorInput {
	return accessservice.AdministratorInput{Actor: actor, UserID: target, ExpectedAuthVersion: 1, ExpectedAccessVersion: 1, ExpectedRoleVersion: 1, Grant: grant}
}

func checkUnusableAdministratorBackups(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, lifecycle *accountservice.UserLifecycle, actor accessservice.Principal, role accessdomain.RoleID) {
	t.Helper()
	backup := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, backup.UserID)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, backup.UserID, role)
	for _, query := range []string{
		`DELETE FROM auth.mfa_totp WHERE user_id=$1`,
		`UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
		`DELETE FROM auth.password_credentials WHERE user_id=$1`,
		`UPDATE auth.users SET status='pending' WHERE id=$1`,
		`UPDATE auth.users SET status='blocked' WHERE id=$1`,
		`UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`,
		`INSERT INTO auth.account_provisions(user_id,actor_id,request_key,fingerprint) VALUES($1,$1,$1,repeat('a',64))`,
	} {
		accessExec(t, db, ctx, query, backup.UserID)
		if _, err := svc.ChangeAdministrator(ctx, administratorCommand(actor, backup.UserID, true)); !errors.Is(err, accessdomain.ErrTargetUnavailable) {
			t.Fatal("unready administrator grant/replay accepted", query, err)
		}
		if _, err := svc.ChangeAdministrator(ctx, administratorCommand(actor, actor.UserID, false)); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("unusable backup accepted for revoke", query, err)
		}
		if _, err := lifecycle.ChangeStatus(ctx, actor, accountdomain.StatusChange{UserID: actor.UserID, ExpectedVersion: 1, Status: accountdomain.StatusBlocked}); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("unusable backup accepted for block", query, err)
		}
		if _, err := lifecycle.Delete(ctx, actor, accountdomain.AccountDeletion{UserID: actor.UserID, ExpectedVersion: 1}); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("unusable backup accepted for delete", query, err)
		}
		accessExec(t, db, ctx, `UPDATE auth.users SET status='active',deleted_at=NULL WHERE id=$1`, backup.UserID)
		accessExec(t, db, ctx, `DELETE FROM auth.account_provisions WHERE user_id=$1`, backup.UserID)
		prepareUsableAdministrator(t, db, ctx, backup.UserID)
	}
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, backup.UserID, role)
}

func checkAdministratorAssignmentRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal, target accountdomain.UserID, version int64) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_administrator_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
		CREATE TRIGGER reject_administrator_audit BEFORE INSERT ON auth.access_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_administrator_audit()`)
	input := administratorCommand(actor, target, true)
	input.ExpectedAccessVersion = version
	if _, err := svc.ChangeAdministrator(ctx, input); err == nil {
		t.Fatal("audit failure committed")
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT access_version=$2 AND NOT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.system) FROM auth.users WHERE id=$1`, target, version).Scan(&intact); err != nil || !intact {
		t.Fatal("partial role assignment", err)
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_administrator_audit ON auth.access_audit; DROP FUNCTION auth.reject_administrator_audit()`)
}

func checkAdministratorConcurrentGrant(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal) {
	t.Helper()
	target := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, target.UserID)
	input := administratorCommand(actor, target.UserID, true)
	call := func() error { _, err := svc.ChangeAdministrator(ctx, input); return err }
	a, b := protectionPair(call, call)
	firstWon := a == nil && errors.Is(b, accessdomain.ErrConflict)
	secondWon := b == nil && errors.Is(a, accessdomain.ErrConflict)
	if !firstWon && !secondWon {
		t.Fatal("concurrent grant must have one winner", a, b)
	}
	input.Grant = false
	input.ExpectedAccessVersion = 2
	if _, err := svc.ChangeAdministrator(ctx, input); err != nil {
		t.Fatal(err)
	}
}

func checkAdministratorRemovalRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, lifecycle *accountservice.UserLifecycle, actor accessservice.Principal, role accessdomain.RoleID) {
	t.Helper()
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, actor.UserID, role)
	for _, action := range []string{"revoke", "block", "delete"} {
		first, second := accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx)
		prepareUsableAdministrator(t, db, ctx, first.UserID)
		prepareUsableAdministrator(t, db, ctx, second.UserID)
		accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$3),($2,$3)`, first.UserID, second.UserID, role)
		a, b := protectionPair(func() error {
			_, err := svc.ChangeAdministrator(ctx, administratorCommand(first, first.UserID, false))
			return err
		}, func() error {
			if action == "revoke" {
				_, err := svc.ChangeAdministrator(ctx, administratorCommand(second, second.UserID, false))
				return err
			}
			if action == "block" {
				_, err := lifecycle.ChangeStatus(ctx, second, accountdomain.StatusChange{UserID: second.UserID, ExpectedVersion: 1, Status: accountdomain.StatusBlocked})
				return err
			}
			_, err := lifecycle.Delete(ctx, second, accountdomain.AccountDeletion{UserID: second.UserID, ExpectedVersion: 1})
			return err
		})
		firstWon := a == nil && errors.Is(b, accountdomain.ErrLastAdministrator)
		secondWon := b == nil && errors.Is(a, accountdomain.ErrLastAdministrator)
		if !firstWon && !secondWon {
			t.Fatal("last usable administrator lost", action, a, b)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_roles ur JOIN auth.users u ON u.id=ur.user_id WHERE ur.role_id=$1 AND u.status='active' AND u.deleted_at IS NULL`, role).Scan(&count); err != nil || count != 1 {
			t.Fatal("unexpected remaining owners", count, err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, actor.UserID, role)
}

func checkAdministratorRevocationWait(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal, role accessdomain.RoleID) {
	t.Helper()
	target := accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, target.UserID)
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Preserve the assertion failure; commit closes the transaction.
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, actor.UserID, role); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := svc.ChangeAdministrator(ctx, administratorCommand(actor, target.UserID, true))
		result <- err
	}()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	until := time.Now().Add(2 * time.Second)
	waiting := false
	for time.Now().Before(until) {
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_administrators_runtime' AND wait_event='advisory')`).Scan(&waiting); err != nil {
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
	if !waiting {
		t.Fatal("system assignment did not wait behind role revoke")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, accessdomain.ErrForbidden) {
			t.Fatal("stale system membership used", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT access_version=1 AND NOT EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1) FROM auth.users WHERE id=$1`, target.UserID).Scan(&intact); err != nil || !intact {
		t.Fatal("unauthorized system grant committed", err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, actor.UserID, role)
}
