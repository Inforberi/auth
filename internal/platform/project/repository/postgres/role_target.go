package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func lockRoleTarget(ctx context.Context, tx pgx.Tx, command domain.RoleCreation) (credentials.Binding, []byte, error) {
	b := credentials.Binding{ProjectID: command.ProjectID}
	var snapshot []byte
	// Lifecycle writers lock the project first; runtime cannot alter private metadata.
	err := tx.QueryRow(ctx, `SELECT realm.id::text,prep.reservation_id::text,p.storage_target,
		s.database_oid,s.owner_oid,s.runtime_oid,s.schema_version,jsonb_build_object(
		'target',p.storage_target,'database',p.database_name,'reservation',s.reservation_id,
		'database_oid',s.database_oid,'owner_oid',s.owner_oid,'runtime_oid',s.runtime_oid,'schema',s.schema_version)
		FROM platform.projects p
		JOIN platform.project_preparations prep ON prep.project_id=p.id AND prep.secrets_created
		JOIN platform.project_secrets s ON s.project_id=p.id AND s.reservation_id=prep.reservation_id
			AND s.storage_target=prep.storage_target AND s.storage_target=p.storage_target AND s.schema_version=p.schema_version
		CROSS JOIN platform.operator_realm realm
		WHERE p.id=$1 AND p.version=$2 AND p.generation=$3 AND p.desired_state='enabled' AND p.phase='ready'
		AND realm.initialized_at IS NOT NULL AND p.database_name='authp_'||replace(p.id::text,'-','')
		FOR SHARE OF p`, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration).Scan(
		&b.RealmID, &b.ReservationID, &b.StorageTarget, &b.DatabaseOID, &b.OwnerOID, &b.RuntimeOID, &b.SchemaVersion, &snapshot,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return credentials.Binding{}, nil, domain.ErrConflict
	}
	return b, snapshot, catalogError(ctx, err)
}
