package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

type DeletionTarget struct {
	Binding          credentials.Binding
	Credential       credentials.DatabaseCredential
	Stage            string
	AcknowledgeUsers bool
	Expired          bool
}

func (r *PreparationRepository) DeletionTarget(ctx context.Context, operation domain.ID, codec *credentials.Codec) (DeletionTarget, error) {
	var target DeletionTarget
	var stored secretRecord
	if codec == nil {
		return target, domain.ErrUnavailable
	}
	err := r.db.QueryRow(ctx, `SELECT d.stage,d.acknowledge_users,d.stage IN ('confirmed','draining') AND d.expires_at<=clock_timestamp(),p.id,s.reservation_id,s.storage_target,
		s.database_oid,s.owner_oid,s.runtime_oid,s.schema_version,s.format_version,s.key_id,s.ciphertext
		FROM platform.project_deletions d JOIN platform.projects p ON p.id=d.project_id
		JOIN platform.project_preparations q ON q.project_id=p.id AND q.secrets_created
		JOIN platform.project_secrets s ON s.project_id=p.id AND s.reservation_id=q.reservation_id
		JOIN platform.operator_realm realm ON realm.id=$3 AND realm.first_operator_id=d.actor_id
		WHERE d.operation_id=$1 AND p.storage_target=$2 AND s.storage_target=$2
		AND p.phase='ready' AND p.desired_state='suspended' AND p.version=d.version AND p.generation=d.generation
		AND p.database_name='authp_'||replace(p.id::text,'-','') AND p.schema_version=s.schema_version`, operation, r.target, r.realm).
		Scan(&target.Stage, &target.AcknowledgeUsers, &target.Expired, &stored.binding.ProjectID, &stored.binding.ReservationID, &stored.binding.StorageTarget,
			&stored.binding.DatabaseOID, &stored.binding.OwnerOID, &stored.binding.RuntimeOID, &stored.binding.SchemaVersion, &stored.version, &stored.keyID, &stored.payload)
	defer clear(stored.payload)
	if err != nil {
		return target, sqlerrors.Catalog(ctx, err)
	}
	stored.binding.RealmID = r.realm
	target.Binding = stored.binding
	target.Credential, err = codec.OpenDatabase(stored.binding, stored.version, stored.keyID, stored.payload)
	return target, err
}

func (r *PreparationRepository) AdvanceDeletion(ctx context.Context, operation domain.ID, from, to string) error {
	tag, err := r.db.Exec(ctx, `UPDATE platform.project_deletions d SET stage=$3 FROM platform.projects p
		WHERE d.operation_id=$1 AND d.stage=$2 AND p.id=d.project_id AND p.storage_target=$4
		AND p.phase='ready' AND p.desired_state='suspended' AND p.version=d.version AND p.generation=d.generation
		AND ($3 NOT IN ('draining','verified') OR d.expires_at>clock_timestamp())`, operation, from, to, r.target)
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrConflict
	}
	return nil
}

func (r *PreparationRepository) NextDeletion(ctx context.Context) (domain.ID, error) {
	var operation domain.ID
	err := r.db.QueryRow(ctx, `WITH chosen AS (
  SELECT d.operation_id FROM platform.project_deletions d JOIN platform.projects p ON p.id=d.project_id
  WHERE p.storage_target=$1 AND p.desired_state='suspended' AND p.version=d.version AND p.generation=d.generation
  AND d.stage IN ('confirmed','draining','verified') AND d.retry_after<=clock_timestamp()
  ORDER BY d.retry_after,d.operation_id LIMIT 1 FOR UPDATE OF d SKIP LOCKED
) UPDATE platform.project_deletions d SET retry_after=clock_timestamp()+interval '30 seconds'
  FROM chosen WHERE d.operation_id=chosen.operation_id RETURNING d.operation_id`, r.target).Scan(&operation)
	return operation, sqlerrors.Catalog(ctx, err)
}
