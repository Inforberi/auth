package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

// ResolveRuntime selects resources for an exact registered origin, never from a user-supplied project ID.
func (r *RuntimeCredentialReader) ResolveRuntime(ctx context.Context, origin string) (projectruntime.Key, error) {
	if !domain.ValidOrigin(origin) {
		return projectruntime.Key{}, domain.ErrInvalidProject
	}
	if r == nil || r.db == nil {
		return projectruntime.Key{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var key projectruntime.Key
	var safe, current bool
	key.Binding.RealmID = r.realm
	err := r.db.QueryRow(ctx, `WITH profile AS MATERIALIZED(SELECT (`+runtimeCredentialProfile+`) AS safe)
 SELECT p.id,p.version,p.generation,p.storage_target,s.reservation_id,
 COALESCE(s.database_oid,0::oid),COALESCE(s.owner_oid,0::oid),COALESCE(s.runtime_oid,0::oid),COALESCE(s.schema_version,0),
 (SELECT safe FROM profile),COALESCE((`+runtimeSnapshotPredicate+`),false)
 FROM `+runtimeSnapshotRelations+`
 CROSS JOIN LATERAL(SELECT $1::uuid AS realm_id,p.id AS project_id,s.reservation_id,
 p.storage_target,s.database_oid,s.owner_oid,s.runtime_oid,s.schema_version,p.version,p.generation) wanted
 WHERE p.origin=$2 AND realm.id=$1`, r.realm, origin).Scan(&key.Binding.ProjectID, &key.Version, &key.Generation, &key.Binding.StorageTarget,
		&key.Binding.ReservationID, &key.Binding.DatabaseOID, &key.Binding.OwnerOID, &key.Binding.RuntimeOID, &key.Binding.SchemaVersion, &safe, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return projectruntime.Key{}, domain.ErrNotFound
	}
	if err != nil {
		return projectruntime.Key{}, sqlerrors.Catalog(ctx, err)
	}
	if !safe {
		return projectruntime.Key{}, domain.ErrUnavailable
	}
	if !current || !key.Valid() {
		return projectruntime.Key{}, domain.ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return projectruntime.Key{}, err
	}
	return key, nil
}
