package platform_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func operatorAuthority(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo, wrong *operators.Repository, owner accountdomain.UserID) {
	t.Helper()
	// Deliberately inserted SQL fixture: this tests authority, not an HTTP login ceremony.
	actor := domain.Principal{UserID: owner, TokenHash: strings.Repeat("a", 64)}
	_, err := db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
		primary_method,primary_verified_at,password_verified_at,mfa_verified_at,user_agent,ip_address)
		VALUES($1,$2,1,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours',
		'password',statement_timestamp(),statement_timestamp(),statement_timestamp(),'operator SQL fixture','192.0.2.1')`, actor.TokenHash, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range domain.OwnerPermissions() {
		if err := repo.AuthorizeRead(ctx, actor, permission); err != nil {
			t.Fatalf("owner permission %s: %v", permission, err)
		}
	}
	if !errors.Is(wrong.AuthorizeRead(ctx, actor, domain.ProjectsRead), domain.ErrForbidden) {
		t.Fatal("session crossed realm boundary")
	}
	for _, test := range []struct{ name, change, restore string }{
		{"revoked", `UPDATE auth.sessions SET revoked_at=clock_timestamp()`, `UPDATE auth.sessions SET revoked_at=NULL`},
		{"expired", `UPDATE auth.sessions SET expires_at=created_at+interval '1 microsecond'`, `UPDATE auth.sessions SET expires_at=clock_timestamp()+interval '10 minutes'`},
		{"blocked", `UPDATE auth.users SET status='blocked'`, `UPDATE auth.users SET status='active'`},
		{"auth version", `UPDATE auth.users SET auth_version=2`, `UPDATE auth.users SET auth_version=1`},
		{"no password proof", `UPDATE auth.sessions SET password_verified_at=NULL`, `UPDATE auth.sessions SET password_verified_at=created_at`},
		{"future password proof", `UPDATE auth.sessions SET password_verified_at=clock_timestamp()+interval '1 minute'`, `UPDATE auth.sessions SET password_verified_at=created_at`},
		{"no MFA proof", `UPDATE auth.sessions SET mfa_verified_at=NULL`, `UPDATE auth.sessions SET mfa_verified_at=primary_verified_at`},
		{"stale role binding", `UPDATE auth.roles SET session_revision=session_revision+1`, `UPDATE auth.roles SET session_revision=session_revision-1`},
		{"no platform permission", `DELETE FROM platform.operator_permissions WHERE permission_key='platform.projects.read'`, `INSERT INTO platform.operator_permissions(user_id,permission_key) SELECT first_operator_id,'platform.projects.read' FROM platform.operator_realm`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.Exec(ctx, test.change); err != nil {
				t.Fatal(err)
			}
			authErr := repo.AuthorizeRead(ctx, actor, domain.ProjectsRead)
			if _, err := db.Exec(ctx, test.restore); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(authErr, domain.ErrForbidden) {
				t.Fatalf("invalid authority admitted: %v", authErr)
			}
		})
	}
	if _, err := db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'platform.projects.read' FROM auth.roles;
		DELETE FROM platform.operator_permissions WHERE permission_key='platform.projects.read'`); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(repo.AuthorizeRead(ctx, actor, domain.ProjectsRead), domain.ErrForbidden) {
		t.Fatal("Auth super-admin/project permission granted platform authority")
	}
	if !errors.Is(repo.AuthorizeRead(ctx, actor, "platform.*"), domain.ErrForbidden) {
		t.Fatal("wildcard permission accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := repo.AuthorizeRead(cancelled, actor, domain.ProjectsRead); !errors.Is(err, context.Canceled) || !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("cancelled SQL check: %v", err)
	}
	var publicAccess bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.table_privileges
		WHERE grantee='PUBLIC' AND table_schema='platform' AND table_name LIKE 'operator%')`).Scan(&publicAccess); err != nil || publicAccess {
		t.Fatal("public operator authority ACL", err)
	}
}
