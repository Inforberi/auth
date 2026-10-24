package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type runtimeProbe struct {
	Ordinal       int       `json:"ordinal"`
	RealmID       domain.ID `json:"realm_id"`
	ProjectID     domain.ID `json:"project_id"`
	ReservationID domain.ID `json:"reservation_id"`
	StorageTarget string    `json:"storage_target"`
	DatabaseOID   uint32    `json:"database_oid"`
	OwnerOID      uint32    `json:"owner_oid"`
	RuntimeOID    uint32    `json:"runtime_oid"`
	SchemaVersion int       `json:"schema_version"`
	Version       int64     `json:"version"`
	Generation    int64     `json:"generation"`
}

func (r *RuntimeCredentialReader) CurrentRuntimes(ctx context.Context, keys []projectruntime.Key) ([]bool, error) {
	if len(keys) == 0 {
		return []bool{}, nil
	}
	if len(keys) > projectruntime.StateBatchSize {
		return nil, domain.ErrInvalidProject
	}
	input := make([]runtimeProbe, len(keys))
	for i, key := range keys {
		b := key.Binding
		if !key.Valid() || b.RealmID != r.realm {
			return nil, domain.ErrConflict
		}
		input[i] = runtimeProbe{
			Ordinal: i, RealmID: b.RealmID, ProjectID: b.ProjectID, ReservationID: b.ReservationID, StorageTarget: b.StorageTarget,
			DatabaseOID: b.DatabaseOID, OwnerOID: b.OwnerOID, RuntimeOID: b.RuntimeOID, SchemaVersion: b.SchemaVersion,
			Version: key.Version, Generation: key.Generation,
		}
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `WITH profile AS MATERIALIZED(SELECT (`+runtimeCredentialProfile+`) AS safe)
		SELECT wanted.ordinal,(SELECT safe FROM profile),EXISTS(SELECT 1 FROM `+runtimeSnapshotRelations+` WHERE `+runtimeSnapshotPredicate+`)
		FROM jsonb_to_recordset($1::jsonb) AS wanted(ordinal int,realm_id uuid,project_id uuid,reservation_id uuid,
			storage_target text,database_oid oid,owner_oid oid,runtime_oid oid,schema_version int,version bigint,generation bigint)
		ORDER BY wanted.ordinal`, payload)
	if err != nil {
		return nil, catalogError(ctx, err)
	}
	defer rows.Close()
	result := make([]bool, 0, len(keys))
	for rows.Next() {
		var ordinal int
		var safe, current bool
		if err := rows.Scan(&ordinal, &safe, &current); err != nil {
			return nil, catalogError(ctx, err)
		}
		if !safe || ordinal != len(result) {
			return nil, domain.ErrUnavailable
		}
		result = append(result, current)
	}
	if err := rows.Err(); err != nil {
		return nil, catalogError(ctx, err)
	}
	if len(result) != len(keys) {
		return nil, domain.ErrUnavailable
	}
	return result, nil
}
