package postgres

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type RuntimeCursor struct {
	CreatedAt time.Time
	ProjectID domain.ID
}

// PageRuntimes discovers work, not authority: consumers must check each exact key again.
func (r *RuntimeCredentialReader) PageRuntimes(ctx context.Context, after RuntimeCursor, limit int) ([]projectruntime.Key, RuntimeCursor, error) {
	if r == nil || limit < 1 || limit > projectruntime.StateBatchSize {
		return nil, RuntimeCursor{}, domain.ErrInvalidProject
	}
	var timestamp any
	var id any
	if !after.CreatedAt.IsZero() || after.ProjectID != "" {
		if after.CreatedAt.IsZero() || !domain.ValidID(after.ProjectID) {
			return nil, RuntimeCursor{}, domain.ErrInvalidProject
		}
		timestamp, id = after.CreatedAt, after.ProjectID
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `WITH candidates AS MATERIALIZED (
  SELECT * FROM platform.projects WHERE phase='ready' AND desired_state='enabled'
  AND ($2::timestamptz IS NULL OR (created_at,id)<($2::timestamptz,$3::uuid))
  ORDER BY created_at DESC,id DESC LIMIT $4
 ), profile AS MATERIALIZED (SELECT (`+runtimeCredentialProfile+`) AS safe)
 SELECT p.created_at,p.id,p.version,p.generation,p.storage_target,
  COALESCE(s.reservation_id,'00000000-0000-0000-0000-000000000000'::uuid),
  COALESCE(s.database_oid,0::oid),COALESCE(s.owner_oid,0::oid),COALESCE(s.runtime_oid,0::oid),COALESCE(s.schema_version,0),
  (SELECT safe FROM profile),COALESCE((`+runtimeSnapshotPredicate+`),false)
 FROM candidates p LEFT JOIN platform.project_preparations prep ON prep.project_id=p.id
 LEFT JOIN platform.project_secrets s ON s.project_id=p.id
 CROSS JOIN platform.operator_realm realm
 CROSS JOIN LATERAL (SELECT $1::uuid AS realm_id,p.id AS project_id,s.reservation_id,
  p.storage_target,s.database_oid,s.owner_oid,s.runtime_oid,s.schema_version,p.version,p.generation) wanted
 WHERE realm.id=$1 ORDER BY p.created_at DESC,p.id DESC`, r.realm, timestamp, id, limit)
	if err != nil {
		return nil, RuntimeCursor{}, sqlerrors.Catalog(ctx, err)
	}
	defer rows.Close()
	keys := make([]projectruntime.Key, 0, limit)
	var next RuntimeCursor
	for rows.Next() {
		var key projectruntime.Key
		var safe, current bool
		key.Binding.RealmID = r.realm
		err := rows.Scan(&next.CreatedAt, &key.Binding.ProjectID, &key.Version, &key.Generation, &key.Binding.StorageTarget,
			&key.Binding.ReservationID, &key.Binding.DatabaseOID, &key.Binding.OwnerOID, &key.Binding.RuntimeOID, &key.Binding.SchemaVersion, &safe, &current)
		if err != nil {
			return nil, RuntimeCursor{}, sqlerrors.Catalog(ctx, err)
		}
		if !safe {
			return nil, RuntimeCursor{}, domain.ErrUnavailable
		}
		next.ProjectID = key.Binding.ProjectID
		// Advance past malformed candidates as well, so one broken project cannot starve later pages.
		if current && key.Valid() {
			keys = append(keys, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, RuntimeCursor{}, sqlerrors.Catalog(ctx, err)
	}
	return keys, next, nil
}
