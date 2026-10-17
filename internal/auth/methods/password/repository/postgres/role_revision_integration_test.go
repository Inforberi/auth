package postgres

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestRoleRevisionSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	accessExec(t, db, ctx, `CREATE ROLE auth_role_revision_runtime LOGIN PASSWORD 'synthetic-recovery-only';
		GRANT USAGE ON SCHEMA auth TO auth_role_revision_runtime;
		GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA auth TO auth_role_revision_runtime`)
	t.Cleanup(func() {
		migrateFixture(t, db, ctx, "down")
		accessExec(t, db, ctx, `DROP ROLE auth_role_revision_runtime`)
	})
	runtime := operatorPool(t, ctx, db, "auth_role_revision_runtime")
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "reports.read", Name: "Read"}, {Key: "reports.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	actor, target, unrelated := accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx), accessPrincipal(t, db, ctx)
	prepareUsableAdministrator(t, db, ctx, target.UserID)
	accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('operator','Operator') RETURNING id),
		p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,unnest($2::text[]) FROM r)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, actor.UserID,
		[]string{"access.roles.manage", "access.assignments.manage", "reports.read", "reports.write"})
	svc := accessservice.New(accesspostgres.New(runtime), catalog)
	role, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "editor", Name: "Editor", Permissions: []accessdomain.PermissionKey{settings.RolesManage, "reports.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, Grant: true}); err != nil {
		t.Fatal(err)
	}
	target = renewAccessPrincipal(t, db, ctx, target.UserID)
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE token_hash=$1`, target.TokenHash, tokens.Hash(raw))
	target.TokenHash = tokens.Hash(raw)
	var passwordHash string
	if err := db.QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id=$1`, target.UserID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	sessions := sessionpostgres.New(runtime)
	prior, err := sessions.FindSession(ctx, target.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	update := func(name string, permissions []accessdomain.PermissionKey) {
		t.Helper()
		role, err = svc.UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{
			Actor: actor, Key: role.Key, Name: name, Permissions: permissions,
		}, RoleID: role.ID, ExpectedVersion: role.Version})
		if err != nil {
			t.Fatal(err)
		}
	}
	update("Renamed editor", role.Permissions)
	update(role.Name, role.Permissions) // A no-op must not advance the security revision either.
	if _, err := sessions.FindSession(ctx, target.TokenHash); err != nil {
		t.Fatal("metadata/no-op invalidated session", err)
	}
	update(role.Name, []accessdomain.PermissionKey{settings.RolesManage, "reports.read", "reports.write"})
	if _, err := sessions.FindSession(ctx, target.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("old session inherited expanded permissions", err)
	}
	if _, err := sessions.FindSession(ctx, unrelated.TokenHash); err != nil {
		t.Fatal("unrelated session invalidated", err)
	}
	if err := svc.Authorize(ctx, target, "reports.write"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("direct authorization bypass", err)
	}
	if _, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: target, Key: "stale_actor", Name: "Stale actor"}); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatal("transaction accepted stale principal", err)
	}
	expected := prior.ExpiresAt
	prior.ExpiresAt = prior.ExpiresAt.Add(time.Minute)
	if _, err := sessions.RefreshSession(ctx, target.TokenHash, prior, expected); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("stale refresh revived session", err)
	}
	if _, err := sessions.RotateSession(ctx, target.UserID, target.TokenHash, unrelated.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("rotation bypassed role revision", err)
	}
	if _, err := sessions.ConfirmPassword(ctx, target.UserID, target.TokenHash, passwordHash, 2, unrelated.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("password proof bypassed role revision", err)
	}
	if _, err := mfapostgres.New(runtime).StepUp(ctx, mfaservice.Proof{UserID: target.UserID, TokenHash: target.TokenHash, AuthVersion: 2}, unrelated.TokenHash, nil, ""); !errors.Is(err, mfadomain.ErrProofRequired) {
		t.Fatal("MFA proof bypassed role revision", err)
	}
	h := router.New(router.Handlers{Access: accesshttp.New(svc, zap.NewNop()), Middleware: sessionhttp.New(
		sessionservice.New(clock.UTCClock{}, sessions, tokens, sessionservice.Config{}), zap.NewNop(),
	), Config: &config.Config{}})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/access", nil)
	r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: raw})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatal("HTTP accepted stale cookie", w.Code, w.Body.String())
	}
	fresh := renewAccessPrincipal(t, db, ctx, target.UserID)
	if err := svc.Authorize(ctx, fresh, "reports.write"); err != nil {
		t.Fatal("new session did not bind current role revision", err)
	}
	if _, err := runtime.Exec(ctx, `UPDATE auth.sessions SET role_revisions='{}' WHERE token_hash=$1`, target.TokenHash); err == nil {
		t.Fatal("issuance binding was mutable")
	}
	update(role.Name, []accessdomain.PermissionKey{settings.RolesManage, "reports.read"})
	if _, err := sessions.FindSession(ctx, fresh.TokenHash); err != nil {
		t.Fatal("permission removal invalidated fresh session", err)
	}
	if err := svc.Authorize(ctx, fresh, "reports.write"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("removed permission remained usable", err)
	}
	checkRoleRevisionRollback(t, db, runtime, ctx, svc, actor, fresh, role)
	role = checkRoleRevisionIssueRace(t, runtime, ctx, svc, actor, fresh, role)
	fresh = renewAccessPrincipal(t, db, ctx, target.UserID)
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: role.Version, ExpectedAccessVersion: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.FindSession(ctx, target.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("removing assignment resurrected stale session", err)
	}
	if _, err := sessions.FindSession(ctx, fresh.TokenHash); err != nil {
		t.Fatal("assignment removal invalidated current session", err)
	}
}

func checkRoleRevisionIssueRace(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor, target accessservice.Principal, role accessdomain.Role) accessdomain.Role {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // Commit closes the transaction; preserve assertion errors.
	digest := tokengenerate.New().Hash("pending-role-login:" + string(target.UserID))
	if _, err := tx.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address)
		SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day','',''
		FROM auth.users WHERE id=$2`, digest, target.UserID); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{
		Actor: actor, Key: role.Key, Name: role.Name, Permissions: []accessdomain.PermissionKey{settings.RolesManage, "reports.read", "reports.write"},
	}, RoleID: role.ID, ExpectedVersion: role.Version})
	if err != nil {
		t.Fatal(err)
	}
	// The login INSERT predates the role edit, even though its transaction commits last.
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, digest); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("late login commit inherited new permission", err)
	}
	var unchanged bool
	if err := db.QueryRow(ctx, `SELECT auth_version=2 AND access_version=2 FROM auth.users WHERE id=$1`, target.UserID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("role edit rewrote user versions", err)
	}
	return updated
}

func checkRoleRevisionRollback(t *testing.T, db, runtime *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor, target accessservice.Principal, role accessdomain.Role) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_role_revision_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
		CREATE TRIGGER reject_role_revision_audit BEFORE INSERT ON auth.access_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_role_revision_audit()`)
	_, err := svc.UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{
		Actor: actor, Key: role.Key, Name: role.Name, Permissions: []accessdomain.PermissionKey{settings.RolesManage, "reports.read", "reports.write"},
	}, RoleID: role.ID, ExpectedVersion: role.Version})
	if err == nil {
		t.Fatal("role edit ignored audit failure")
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_role_revision_audit ON auth.access_audit; DROP FUNCTION auth.reject_role_revision_audit()`)
	if _, err := sessionpostgres.New(runtime).FindSession(ctx, target.TokenHash); err != nil {
		t.Fatal("rolled-back edit invalidated session", err)
	}
	current, err := svc.ReadRole(ctx, role.ID)
	if err != nil || current.Version != role.Version {
		t.Fatal("role version changed after rollback", current, err)
	}
}
