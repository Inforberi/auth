package projects_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkEmailMFARoleTransitions(t *testing.T, f emailMFAHTTPFixture, owner string) {
	t.Helper()
	ctx := t.Context()
	db := f.projects.databases[0]
	var role accessdomain.RoleID
	require.NoError(t, db.QueryRow(ctx, `INSERT INTO auth.roles(key,name) VALUES('email_mfa_candidate','Email MFA candidate') RETURNING id`).Scan(&role))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE role_id=$1`, role)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.access_audit WHERE role_id=$1`, role)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.roles WHERE id=$1`, role)
		require.NoError(t, err)
	})
	_, err := db.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, httpIsolationUser, role)
	require.NoError(t, err)
	actor := accessservice.Principal{UserID: accountdomain.UserID(httpOwnerID), TokenHash: tokengenerate.New().Hash(strings.TrimPrefix(owner, "__Host-session="))}
	err = f.projects.deps.Registry.UsePool(ctx, f.projects.projects[0], func(ctx context.Context, pool *pgxpool.Pool) error {
		_, err := accesspostgres.NewWithMFA(pool, true).UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: "email_mfa_candidate", Name: "Email MFA candidate", Permissions: []accessdomain.PermissionKey{"auth.settings.manage"}}, RoleID: role, ExpectedVersion: 1})
		return err
	})
	require.ErrorIs(t, err, accessdomain.ErrConflict, "role update must not strand email-only members as administrators")
	var count int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.role_permissions WHERE role_id=$1`, role).Scan(&count))
	require.Zero(t, count, "failed role transition must roll back permissions")
	_, err = db.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, httpIsolationUser, role)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) VALUES($1,'auth.settings.manage')`, role)
	require.NoError(t, err)
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer func(tx pgx.Tx) { _ = tx.Rollback(context.WithoutCancel(ctx)) }(tx)
	require.NoError(t, accesspostgres.LockAccessChanges(ctx, tx))
	var version int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT access_version FROM auth.users WHERE id=$1 FOR UPDATE`, httpIsolationUser).Scan(&version))
	_, _, err = accesspostgres.ApplyAssignmentInTransaction(ctx, tx, accountdomain.UserID(httpIsolationUser), role, true, version)
	require.ErrorIs(t, err, accessdomain.ErrConflict, "grant must require TOTP for an email-only administrative target")
	require.NoError(t, tx.Rollback(ctx))
	var assigned bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2)`, httpIsolationUser, role).Scan(&assigned))
	require.False(t, assigned)
	tx, err = db.Begin(ctx)
	require.NoError(t, err)
	defer func(tx pgx.Tx) { _ = tx.Rollback(context.WithoutCancel(ctx)) }(tx)
	require.NoError(t, accesspostgres.LockAccessChanges(ctx, tx))
	require.NoError(t, tx.QueryRow(ctx, `SELECT access_version FROM auth.users WHERE id=$1 FOR UPDATE`, httpIsolationUser).Scan(&version))
	secret, err := f.mfa[0].Seal([]byte(httpIsolationUser + "\x00JBSWY3DPEHPK3PXP"))
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, httpIsolationUser, secret)
	require.NoError(t, err)
	_, changed, err := accesspostgres.ApplyAssignmentInTransaction(ctx, tx, accountdomain.UserID(httpIsolationUser), role, true, version)
	require.NoError(t, err, "a target with TOTP must remain eligible")
	require.True(t, changed)
	require.NoError(t, tx.Rollback(ctx))
	var authVersion accountdomain.AuthVersion
	var superVersion int64
	require.NoError(t, db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&authVersion))
	require.NoError(t, db.QueryRow(ctx, `SELECT version FROM auth.roles WHERE key='super_admin' AND system`).Scan(&superVersion))
	err = f.projects.deps.Registry.UsePool(ctx, f.projects.projects[0], func(ctx context.Context, pool *pgxpool.Pool) error {
		_, err := accesspostgres.NewWithMFA(pool, true).ChangeAdministrator(ctx, accessservice.AdministratorInput{Actor: actor, UserID: accountdomain.UserID(httpIsolationUser), ExpectedAuthVersion: authVersion, ExpectedAccessVersion: version, ExpectedRoleVersion: superVersion, Grant: true})
		return err
	})
	require.ErrorIs(t, err, accessdomain.ErrTargetUnavailable)
	tx, err = db.Begin(ctx)
	require.NoError(t, err)
	defer func(tx pgx.Tx) { _ = tx.Rollback(context.WithoutCancel(ctx)) }(tx)
	require.NoError(t, accesspostgres.LockAccessChanges(ctx, tx))
	require.ErrorIs(t, accesspostgres.RequireAdministratorRemains(ctx, tx, accountdomain.UserID(httpOwnerID)), accountdomain.ErrLastAdministrator)
	require.NoError(t, tx.Rollback(ctx))
}
