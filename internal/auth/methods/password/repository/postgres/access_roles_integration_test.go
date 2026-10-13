package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessrepo "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
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
	version, err := svc.ChangeAssignment(ctx, assignment)
	if err != nil || version != 2 {
		t.Fatalf("grant: %d %v", version, err)
	}
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
	assignment.Grant = false
	if version, err := svc.ChangeAssignment(ctx, assignment); err != nil || version != 3 {
		t.Fatalf("revoke: %d %v", version, err)
	}
	if err := svc.Authorize(ctx, target, "reports.read"); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatalf("immediate revoke: %v", err)
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
	checkAccessRaces(t, ctx, svc, actor, other, role)
	checkAccessRoleLimit(t, db, ctx, svc, actor, role)
	checkAccessCatalog(t, db, ctx, role)
	checkAccessAuditRollback(t, db, ctx, svc, actor)
	checkAccessSessionGuards(t, db, ctx, svc, other, actor)
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.access_audit WHERE role_id=$1`, role.ID).Scan(&count); err != nil || count != 6 {
		t.Fatalf("audit count excludes no-op/failed writes: %d %v", count, err)
	}
}

func checkAccessRaces(t *testing.T, ctx context.Context, svc *accessservice.Service, actor, target accessservice.Principal, role accessdomain.Role) {
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

func checkAccessAuditRollback(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *accessservice.Service, actor accessservice.Principal) {
	t.Helper()
	accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_access_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$;
		CREATE TRIGGER reject_access_audit BEFORE INSERT ON auth.access_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_access_audit()`)
	_, err := svc.CreateRole(ctx, accessservice.CreateRoleInput{Actor: actor, Key: "rollback_reader", Name: "Rollback reader", Permissions: []accessdomain.PermissionKey{"reports.read"}})
	if err == nil {
		t.Fatal("audit failure accepted")
	}
	accessExec(t, db, ctx, `DROP TRIGGER reject_access_audit ON auth.access_audit; DROP FUNCTION auth.reject_access_audit()`)
	var present bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.roles WHERE key='rollback_reader')`).Scan(&present); err != nil || present {
		t.Fatalf("audit rollback: %t %v", present, err)
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

func accessExec(t *testing.T, db *pgxpool.Pool, ctx context.Context, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(ctx, query, args...); err != nil {
		t.Fatal(fmt.Errorf("access fixture: %w", err))
	}
}
