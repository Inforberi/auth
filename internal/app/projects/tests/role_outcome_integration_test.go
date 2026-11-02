package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

func roleOutcomeDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal,
	command domain.RoleCreation, registry *projectruntime.Registry, created domain.RoleCreationResult,
) {
	t.Helper()
	ctx := t.Context()
	_, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.projects.read')`, actor.UserID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `WITH cleared AS (
			DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read')
			INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_access.manage') ON CONFLICT DO NOTHING`, actor.UserID)
		require.NoError(t, err)
	})
	known, err := managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.NoError(t, err)
	require.True(t, known.Committed)
	otherProject := domain.ID("a2000000-0000-4000-8000-000000000099")
	_, err = managed.ReadRoleOutcome(ctx, actor, otherProject, command.OperationID)
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = managed.ReconcileRoleOutcome(ctx, actor, otherProject, command.OperationID, nil)
	require.ErrorIs(t, err, domain.ErrNotFound, "project scope must be checked before any runtime access")
	require.Equal(t, created.Role, known.Role)
	pending := command
	pending.OperationID, pending.Key = "f2000000-0000-4000-8000-000000000017", "bridge_drill_pending"
	_, err = managed.PrepareRoleCreation(ctx, actor, pending)
	require.NoError(t, err)
	_, err = managed.AdmitRoleCreation(ctx, actor, pending)
	require.NoError(t, err)
	unresolved, err := managed.ReconcileRoleOutcome(ctx, actor, pending.ProjectID, pending.OperationID, registry)
	require.NoError(t, err)
	require.False(t, unresolved.Committed, "missing receipt is unknown, never evidence of rollback or permission to create")
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`, actor.UserID)
	require.NoError(t, err)
	_, err = managed.AdmitRoleCreation(ctx, actor, command)
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
	known, err = managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.NoError(t, err, "read-own completion needs current read permission, not the removed write permission")
	require.True(t, known.Committed)
	var admissionsBefore int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&admissionsBefore))
	_, err = admin.Exec(ctx, `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, command.OperationID)
	require.NoError(t, err)
	unknown, err := managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.NoError(t, err)
	require.False(t, unknown.Committed)
	require.Empty(t, unknown.Role.ID)
	// Restore completion evidence from the immutable project receipt, without issuing authority.
	known, err = managed.ReconcileRoleOutcome(ctx, actor, command.ProjectID, command.OperationID, registry)
	require.NoError(t, err)
	require.True(t, known.Committed)
	require.Equal(t, created.Role, known.Role)
	var admissionsAfter int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, command.OperationID).Scan(&admissionsAfter))
	require.Equal(t, admissionsBefore, admissionsAfter)
	// Own and foreign operation IDs have the same not-found result for this reader.
	_, err = managed.ReadRoleOutcome(ctx, actor, command.ProjectID, "f2000000-0000-4000-8000-000000000099")
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = admin.Exec(ctx, `UPDATE platform.project_role_intents SET actor_id='d2000000-0000-4000-8000-000000000099' WHERE operation_id=$1`, command.OperationID)
	require.NoError(t, err)
	_, err = managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = admin.Exec(ctx, `UPDATE platform.project_role_intents SET actor_id=$2 WHERE operation_id=$1`, command.OperationID, actor.UserID)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	_, err = managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
	_, err = managed.ReconcileRoleOutcome(ctx, actor, command.ProjectID, command.OperationID, registry)
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET revoked_at=NULL WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, actor.UserID)
	require.NoError(t, err)
	_, err = managed.ReadRoleOutcome(ctx, actor, command.ProjectID, command.OperationID)
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
}
