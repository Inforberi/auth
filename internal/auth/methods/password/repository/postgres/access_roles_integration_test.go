package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessrepo "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkAccessRoles(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "reports.read", Name: "Read reports"}, {Key: "secret.read", Name: "Read secrets"}})
	if err != nil {
		t.Fatal(err)
	}
	svc := accessservice.New(accessrepo.New(db), catalog)
	actor := accessPrincipal(t, db, ctx)
	target := accessPrincipal(t, db, ctx)
	other := accessPrincipal(t, db, ctx)
	var systemID accessdomain.RoleID
	if err := db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES ('super_admin','Super admin',true) RETURNING id`).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[])`, systemID, []string{"access.roles.manage", "access.assignments.manage", "reports.read"})
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2)`, actor.UserID, systemID)
	input := accessservice.CreateRoleInput{Actor: actor, Key: "report_reader", Name: "Report reader", Permissions: []accessdomain.PermissionKey{"reports.read"}}
	role, err := svc.CreateRole(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	read, err := svc.ReadRole(ctx, role.ID)
	if err != nil || len(read.Permissions) != 1 || read.Permissions[0] != "reports.read" {
		t.Fatalf("role read: %+v %v", read, err)
	}
	list, err := svc.ListRoles(ctx, "", 1)
	if err != nil || len(list) != 1 {
		t.Fatalf("bounded list: %v %v", list, err)
	}
	list, err = svc.ListRoles(ctx, list[0].Key, 1)
	if err != nil || len(list) != 1 || list[0].Key != "super_admin" {
		t.Fatalf("keyset list: %v %v", list, err)
	}
	if _, err := svc.CreateRole(ctx, input); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	input.Key = "unauthorized"
	input.Permissions = []accessdomain.PermissionKey{"secret.read"}
	if _, err := svc.CreateRole(ctx, input); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("delegation: %v", err)
	}
	input.Actor = target
	input.Permissions = []accessdomain.PermissionKey{"reports.read"}
	if _, err := svc.CreateRole(ctx, input); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("missing management: %v", err)
	}
	assignment := accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, Grant: true}
	parallelSession := renewAccessPrincipal(t, db, ctx, target.UserID)
	prior, err := sessionpostgres.New(db).FindSession(ctx, target.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	version, err := svc.ChangeAssignment(ctx, assignment)
	if err != nil || version != 2 {
		t.Fatalf("grant: %d %v", version, err)
	}
	for _, credential := range []string{target.TokenHash, parallelSession.TokenHash} {
		if _, err := sessionpostgres.New(db).FindSession(ctx, credential); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatalf("pre-grant session retained authority: %v", err)
		}
	}
	expectedExpiry := prior.ExpiresAt
	prior.ExpiresAt = prior.ExpiresAt.Add(time.Minute)
	if _, err := sessionpostgres.New(db).RefreshSession(ctx, target.TokenHash, prior, expectedExpiry); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatalf("pre-grant refresh restored authority: %v", err)
	}
	if err := svc.Authorize(ctx, target, "reports.read"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("pre-grant session inherited permission: %v", err)
	}
	target = renewAccessPrincipal(t, db, ctx, target.UserID)
	if err := svc.Authorize(ctx, target, "reports.read"); err != nil {
		t.Fatal(err)
	}
	access, err := svc.UserAccess(ctx, target)
	if err != nil || access.Version != 2 || len(access.RoleIDs) != 1 || len(access.Permissions) != 1 || access.Permissions[0] != "reports.read" {
		t.Fatalf("effective access: %+v %v", access, err)
	}
	if err := svc.Authorize(ctx, other, "reports.read"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("foreign user access: %v", err)
	}
	assignment.ExpectedAccessVersion = 2
	if version, err := svc.ChangeAssignment(ctx, assignment); err != nil || version != 2 {
		t.Fatalf("no-op grant: %d %v", version, err)
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, target.TokenHash); err != nil {
		t.Fatalf("no-op grant invalidated current session: %v", err)
	}
	assignment.Grant = false
	if version, err := svc.ChangeAssignment(ctx, assignment); err != nil || version != 3 {
		t.Fatalf("revoke: %d %v", version, err)
	}
	if err := svc.Authorize(ctx, target, "reports.read"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("immediate revoke: %v", err)
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, target.TokenHash); err != nil {
		t.Fatalf("revoke unnecessarily invalidated current session: %v", err)
	}
	assignment.RoleID = systemID
	assignment.UserID = actor.UserID
	if _, err := svc.ChangeAssignment(ctx, assignment); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("system revoke: %v", err)
	}
	update := accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: "report_reader", Name: "Updated reader", Permissions: []accessdomain.PermissionKey{"reports.read"}}, RoleID: role.ID, ExpectedVersion: 1}
	updated, err := svc.UpdateRole(ctx, update)
	if err != nil || updated.Version != 2 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if _, err := svc.UpdateRole(ctx, update); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatalf("stale edit: %v", err)
	}
	update.ExpectedVersion = 2
	if updated, err := svc.UpdateRole(ctx, update); err != nil || updated.Version != 2 {
		t.Fatalf("no-op edit: %+v %v", updated, err)
	}
	update.RoleID, update.ExpectedVersion = systemID, 1
	if _, err := svc.UpdateRole(ctx, update); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("system edit: %v", err)
	}
	checkAccessRaces(t, db, ctx, svc, actor, other, role)
	checkAccessRoleLimit(t, db, ctx, svc, actor, role)
	checkAccessCatalog(t, db, ctx, role)
	checkAccessAuditRollback(t, db, ctx, svc, actor, role.ID)
	checkPendingAssignment(t, db, ctx, svc, actor)
	checkAccessSessionGuards(t, db, ctx, svc, other, actor)
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.access_audit WHERE role_id=$1`, role.ID).Scan(&count); err != nil || count != 6 {
		t.Fatalf("audit count excludes no-op/failed writes: %d %v", count, err)
	}
}

func checkAccessRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor, target accessservice.Principal, role accessdomain.Role) {
	t.Helper()
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			_, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: 2, ExpectedAccessVersion: 1, Grant: true})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, accessdomain.ErrConflict) {
			t.Fatalf("assignment race: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("assignment winners: %d", winners)
	}
	var authVersion int64
	if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, target.UserID).Scan(&authVersion); err != nil || authVersion != 2 {
		t.Fatalf("concurrent grant invalidated more than once: %d %v", authVersion, err)
	}
	results = make(chan error, 16)
	for i := range 16 {
		wg.Go(func() {
			_, err := svc.UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: role.Key, Name: fmt.Sprintf("Concurrent reader %d", i), Permissions: role.Permissions}, RoleID: role.ID, ExpectedVersion: 2})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners = 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, accessdomain.ErrConflict) {
			t.Fatalf("role race: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("role edit winners: %d", winners)
	}
}

func checkAccessRoleLimit(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal, role accessdomain.Role) {
	t.Helper()
	target := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH roles AS (INSERT INTO auth.roles(key,name) SELECT 'bounded_'||i,'Bounded role' FROM generate_series(1,32) i RETURNING id)
		INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM roles`, target.UserID)
	if _, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: 3, ExpectedAccessVersion: 1, Grant: true}); !errors.Is(err, accessdomain.ErrConflict) {
		t.Fatalf("role limit: %v", err)
	}
	access, err := svc.UserAccess(ctx, target)
	if err != nil || len(access.RoleIDs) != 32 || len(access.Permissions) != 0 {
		t.Fatalf("bounded effective access: %+v %v", access, err)
	}
}

func checkAccessAuditRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal, roleID accessdomain.RoleID) {
	t.Helper()
	role, err := svc.ReadRole(ctx, roleID)
	if err != nil {
		t.Fatal(err)
	}
	target := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_access_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$;
		CREATE TRIGGER reject_access_audit BEFORE INSERT ON auth.access_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_access_audit()`)
	_, err = svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "rollback_reader", Name: "Rollback reader", Permissions: []accessdomain.PermissionKey{"reports.read"}})
	if err == nil {
		t.Fatal("audit failure accepted")
	}
	_, err = svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target.UserID, RoleID: role.ID, ExpectedRoleVersion: role.Version, ExpectedAccessVersion: 1, Grant: true})
	if err == nil {
		t.Fatal("grant ignored audit failure")
	}
	var intact bool
	if err := db.QueryRow(ctx, `SELECT auth_version=1 AND access_version=1 AND NOT EXISTS(
		SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2) FROM auth.users WHERE id=$1`, target.UserID, role.ID).Scan(&intact); err != nil || !intact {
		t.Fatalf("grant/version rollback: %t %v", intact, err)
	}
	if _, err := sessionpostgres.New(db).FindSession(ctx, target.TokenHash); err != nil {
		t.Fatalf("rolled-back grant invalidated session: %v", err)
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_access_audit ON auth.access_audit; DROP FUNCTION auth.reject_access_audit()`)
	var present bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.roles WHERE key='rollback_reader')`).Scan(&present); err != nil || present {
		t.Fatalf("audit rollback: %t %v", present, err)
	}
}

func checkPendingAssignment(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal) {
	t.Helper()
	role, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "pending_reader", Name: "Pending reader", Permissions: []accessdomain.PermissionKey{"reports.read"}})
	if err != nil {
		t.Fatal(err)
	}
	var target accountdomain.UserID
	if err := db.QueryRow(ctx, `INSERT INTO auth.users(status) VALUES('pending') RETURNING id`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	version, err := svc.ChangeAssignment(ctx, accessservice.AssignmentInput{Actor: actor, UserID: target, RoleID: role.ID, ExpectedRoleVersion: 1, ExpectedAccessVersion: 1, Grant: true})
	if err != nil || version != 2 {
		t.Fatalf("pending grant: %d %v", version, err)
	}
	var authVersion int64
	if err := db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, target).Scan(&authVersion); err != nil || authVersion != 1 {
		t.Fatalf("pending grant invalidated onboarding version: %d %v", authVersion, err)
	}
}

func checkAccessSessionGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, target, actor accessservice.Principal) {
	t.Helper()
	for _, query := range []string{
		`UPDATE auth.sessions SET mfa_verified_at=NULL WHERE token_hash=$1`,
		`UPDATE auth.sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes',primary_verified_at=clock_timestamp()-interval '7 minutes' WHERE token_hash=$1`,
	} {
		accessExec(t, db, ctx, query, actor.TokenHash)
		if _, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "without_mfa", Name: "Forbidden"}); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
			t.Fatal("administrative operation without fresh MFA", err)
		}
	}
	accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, actor.TokenHash)
	if _, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "stale_reader", Name: "Stale reader"}); !errors.Is(err, accessdomain.ErrFreshAuthRequired) {
		t.Fatalf("fresh proof: %v", err)
	}
	for _, query := range []string{
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`,
		`UPDATE auth.sessions SET revoked_at=NULL,expires_at=clock_timestamp()-interval '1 second',created_at=clock_timestamp()-interval '1 day' WHERE user_id=$1`,
		`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		`UPDATE auth.users SET status='blocked' WHERE id=$1`,
		`UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`,
	} {
		accessExec(t, db, ctx, `UPDATE auth.users SET status='active',deleted_at=NULL,auth_version=1 WHERE id=$1`, target.UserID)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=NULL,auth_version=1,expires_at=clock_timestamp()+interval '1 hour' WHERE user_id=$1`, target.UserID)
		if err := svc.Authorize(ctx, target, "reports.read"); err != nil {
			t.Fatalf("guard baseline: %v", err)
		}
		accessExec(t, db, ctx, query, target.UserID)
		if err := svc.Authorize(ctx, target, "reports.read"); !errors.Is(err, accessdomain.ErrForbidden) {
			t.Fatalf("session/account guard: %v", err)
		}
	}
}

func accessPrincipal(t *testing.T, db *pgxpool.Pool, ctx context.Context) accessservice.Principal {
	t.Helper()
	var id accountdomain.UserID
	if err := db.QueryRow(ctx, `INSERT INTO auth.users DEFAULT VALUES RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(id))
	principal := accessservice.Principal{UserID: id, TokenHash: hex.EncodeToString(digest[:])}
	accessExec(t, db, ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,password_verified_at,user_agent,ip_address)
		VALUES ($1,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day',clock_timestamp(),'','')`, principal.TokenHash, id)
	// Synthetic proofs for the internal Access fixture; real proofs come from MFA login/step-up tests.
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES ($1,$2,0)`, id, make([]byte, 48))
	accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_method='password',primary_verified_at=password_verified_at,
		mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, principal.TokenHash)
	return principal
}

// Synthetic new-login proof; never upgrade the pre-grant session in place.
func renewAccessPrincipal(t *testing.T, db *pgxpool.Pool, ctx context.Context, id accountdomain.UserID) accessservice.Principal {
	t.Helper()
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	principal := accessservice.Principal{UserID: id, TokenHash: tokens.Hash(raw)}
	accessExec(t, db, ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
		password_verified_at,primary_method,primary_verified_at,mfa_verified_at,user_agent,ip_address)
		SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day',
		clock_timestamp(),'password',clock_timestamp(),clock_timestamp(),'','' FROM auth.users WHERE id=$2`, principal.TokenHash, id)
	return principal
}

func accessExec(t *testing.T, db *pgxpool.Pool, ctx context.Context, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(ctx, query, args...); err != nil {
		t.Fatal(fmt.Errorf("access fixture: %w", err))
	}
}
