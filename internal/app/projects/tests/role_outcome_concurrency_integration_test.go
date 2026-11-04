package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	rolespostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/repository/postgres"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

func roleOutcomeConcurrencyDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository,
	actor operatordomain.Principal, command domain.RoleCreation, binding credentials.Binding, registry *projectruntime.Registry, created domain.RoleCreationResult,
) {
	t.Helper()
	ctx := t.Context()
	cfg := admin.Config().Copy()
	var err error
	cfg.Database, _, err = (domain.PreparationReservation{ProjectID: command.ProjectID, ReservationID: binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	project, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, project.Close(cleanup))
	}()
	_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key)
		VALUES($1,'platform.projects.read') ON CONFLICT DO NOTHING`, actor.UserID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, actor.UserID)
		require.NoError(t, err)
	})
	var admissionsBefore int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&admissionsBefore))
	for _, tc := range []struct {
		name, change, restore string
		args                  []any
		denied                bool
	}{
		{"session", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, `UPDATE auth.sessions SET revoked_at=NULL WHERE token_hash=$1`, []any{actor.TokenHash}, true},
		{"read permission", `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.projects.read')`, []any{actor.UserID}, true},
		{"factor", `DELETE FROM auth.mfa_totp WHERE user_id=$1`, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,decode(repeat('11',64),'hex'),0)`, []any{actor.UserID}, true},
		{"auth version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, `UPDATE auth.users SET auth_version=auth_version-1 WHERE id=$1`, []any{actor.UserID}, true},
		{"write permission", `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_access.manage')`, []any{actor.UserID}, false},
		{"suspend", `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, []any{command.ProjectID}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bounded, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			_, err := admin.Exec(bounded, `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID)
			require.NoError(t, err)
			blocker, err := project.Begin(bounded)
			require.NoError(t, err)
			defer func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(bounded), time.Second)
				defer stop()
				_ = blocker.Rollback(cleanup)
			}()
			_, err = blocker.Exec(bounded, `LOCK TABLE auth.platform_role_creations IN ACCESS EXCLUSIVE MODE`)
			require.NoError(t, err)
			finished := make(chan error, 1)
			go func() {
				_, e := roleservice.NewRoles(rolespostgres.NewRuntimeRoles(managed, registry, accesssettings.Catalog{})).ReconcileRoleOutcome(bounded, actor, command.ProjectID, command.OperationID)
				finished <- e
			}()
			waitRoleSQL(t, bounded, blocker, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
				AND wait_event_type='Lock' AND query LIKE '%FROM auth.platform_role_creations WHERE operation_id=%')`)
			// Initial authority has already passed; revoke while receipt reading is blocked.
			_, err = admin.Exec(bounded, tc.change, tc.args...)
			require.NoError(t, err)
			defer func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(bounded), time.Second)
				defer stop()
				_, restoreErr := admin.Exec(cleanup, tc.restore, tc.args...)
				require.NoError(t, restoreErr)
			}()
			require.NoError(t, blocker.Commit(bounded))
			reconcileErr := <-finished
			if tc.denied {
				require.ErrorIs(t, reconcileErr, operatordomain.ErrForbidden)
			} else {
				require.NoError(t, reconcileErr, "write revoke/suspend does not erase an admitted result on a warm runtime")
			}
			var recovered bool
			require.NoError(t, admin.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM platform.project_role_outcomes WHERE operation_id=$1)`, command.OperationID).Scan(&recovered))
			require.True(t, recovered, "completion evidence may be retained even when final disclosure is refused")
		})
	}
	t.Run("parallel reconciliation preserves one receipt", func(t *testing.T) {
		bounded, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, err := admin.Exec(bounded, `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID)
		require.NoError(t, err)
		var receiptXmin string
		require.NoError(t, project.QueryRow(bounded, `SELECT xmin::text FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID).Scan(&receiptXmin))
		start, finished := make(chan struct{}), make(chan error, 4)
		for range 4 {
			go func() {
				<-start
				outcome, e := roleservice.NewRoles(rolespostgres.NewRuntimeRoles(managed, registry, accesssettings.Catalog{})).ReconcileRoleOutcome(bounded, actor, command.ProjectID, command.OperationID)
				if e == nil && (!outcome.Committed || outcome.Role.ID != created.Role.ID) {
					e = domain.ErrConflict
				}
				finished <- e
			}()
		}
		close(start)
		for range 4 {
			require.NoError(t, <-finished)
		}
		known, err := managed.ReadRoleOutcome(bounded, actor, command.ProjectID, command.OperationID)
		require.NoError(t, err)
		require.Equal(t, created.Role, known.Role)
		var unchanged bool
		require.NoError(t, project.QueryRow(bounded, `SELECT xmin::text=$2 FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID, receiptXmin).Scan(&unchanged))
		require.True(t, unchanged, "reconciliation must not rewrite project receipt/audit")
		var admissionsAfter, outcomes int
		require.NoError(t, admin.QueryRow(bounded, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&admissionsAfter))
		require.NoError(t, admin.QueryRow(bounded, `SELECT count(*) FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID).Scan(&outcomes))
		require.Equal(t, admissionsBefore, admissionsAfter, "reconciliation must not issue new admissions")
		require.Equal(t, 1, outcomes)
	})
}
