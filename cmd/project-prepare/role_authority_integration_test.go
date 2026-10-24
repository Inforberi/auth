package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func roleFaultDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal, base domain.RoleCreation,
	registry *projectruntime.Registry, key projectruntime.Key, reader *catalog.RuntimeCredentialReader, ca *x509.CertPool, permissions settings.Catalog,
) {
	t.Helper()
	for i, tc := range []struct {
		name    string
		change  string
		restore string
		args    []any
	}{
		{"session", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, `UPDATE auth.sessions SET revoked_at=NULL WHERE token_hash=$1`, []any{actor.TokenHash}},
		{
			"permission", `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`,
			`INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_access.manage') ON CONFLICT DO NOTHING`,
			[]any{actor.UserID},
		},
		{
			"factor", `DELETE FROM auth.mfa_totp WHERE user_id=$1`,
			`INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,decode(repeat('11',64),'hex'),0) ON CONFLICT DO NOTHING`,
			[]any{actor.UserID},
		},
		{"suspend", `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, []any{base.ProjectID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				_, err := admin.Exec(cleanup, tc.restore, tc.args...)
				require.NoError(t, err)
			})
			command := base
			command.OperationID = domain.ID(fmt.Sprintf("f2000000-0000-4000-8000-%012d", 31+i))
			command.Key = "bridge_fault_" + tc.name
			_, err := managed.PrepareRoleCreation(ctx, actor, command)
			require.NoError(t, err)
			cfg, err := pgxpool.ParseConfig(admin.Config().ConnString())
			require.NoError(t, err)
			cfg.ConnConfig.User, cfg.ConnConfig.Password = "auth_platform_api_secrets_test", "api-fixture-only"
			cfg.ConnConfig.RuntimeParams["application_name"] = command.Key
			cfg.MaxConns, cfg.MinConns = 1, 0
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			authority, err := operators.New(pool, operatordomain.RealmID(key.Binding.RealmID))
			require.NoError(t, err)
			repo, err := catalog.NewManaged(pool, authority, 5*time.Minute, domain.CreationPolicy{
				AuthDomain: "auth.example", PlatformOrigin: "https://console.auth.example", StorageTarget: key.Binding.StorageTarget,
			})
			require.NoError(t, err)
			blocker, err := admin.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = blocker.Rollback(ctx) }()
			_, err = blocker.Exec(ctx, tc.change, tc.args...)
			require.NoError(t, err)
			attempt := make(chan error, 1)
			go func() { _, err := repo.AdmitRoleCreation(ctx, actor, command); attempt <- err }()
			// Observe a real lock wait, rather than guessing ordering from a sleep.
			waitRoleSQL(t, ctx, blocker, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')`, command.Key)
			require.NoError(t, blocker.Commit(ctx))
			require.Error(t, <-attempt, "revocation committed before admission must refuse the command")
			var count int
			require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&count))
			require.Zero(t, count)
			_, err = admin.Exec(ctx, tc.restore, tc.args...)
			require.NoError(t, err)
			admitted, err := repo.AdmitRoleCreation(ctx, actor, command)
			require.NoError(t, err)
			_, err = admin.Exec(ctx, tc.change, tc.args...)
			require.NoError(t, err)
			_, err = repo.AdmitRoleCreation(ctx, actor, command)
			require.Error(t, err)
			result, executionErr := admitted.ExecuteWithRuntime(ctx, registry, permissions, true)
			_, restoreErr := admin.Exec(ctx, tc.restore, tc.args...)
			require.NoError(t, restoreErr)
			require.NoError(t, executionErr, "committed admission may finish on its existing exact lease")
			require.True(t, result.CatalogRecorded)
		})
	}
	t.Run("transport", func(t *testing.T) {
		roleTransportDrill(t, admin, managed, actor, base, registry, key, reader, ca, permissions)
	})
}

func waitRoleSQL(t *testing.T, ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sql string, args ...any,
) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		// pg_stat_activity snapshots otherwise stay cached inside the blocker transaction.
		var cleared any
		require.NoError(t, db.QueryRow(ctx, `SELECT pg_stat_clear_snapshot()`).Scan(&cleared))
		var ready bool
		require.NoError(t, db.QueryRow(ctx, sql, args...).Scan(&ready))
		if ready {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("SQL coordination did not reach its expected state")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}
