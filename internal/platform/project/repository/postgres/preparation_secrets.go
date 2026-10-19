package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

const secretColumns = `reservation_id::text,storage_target,database_oid,owner_oid,runtime_oid,schema_version,format_version,key_id,ciphertext`

type secretRecord struct {
	binding credentials.Binding
	version int
	keyID   string
	payload []byte
}

func scanSecret(row pgx.Row, realm, project domain.ID) (secretRecord, error) {
	var stored secretRecord
	stored.binding.RealmID, stored.binding.ProjectID = realm, project
	err := row.Scan(&stored.binding.ReservationID, &stored.binding.StorageTarget, &stored.binding.DatabaseOID, &stored.binding.OwnerOID,
		&stored.binding.RuntimeOID, &stored.binding.SchemaVersion, &stored.version, &stored.keyID, &stored.payload)
	return stored, err
}

// EnsureSecrets never enables LOGIN. The retained creation flag makes lost ciphertext fail closed.
func (r *PreparationRepository) EnsureSecrets(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) error {
	if codec == nil || binding.RealmID != r.realm || binding.ProjectID != reservation.ProjectID || binding.ReservationID != reservation.ReservationID || binding.StorageTarget != r.target {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.CheckRuntime(ctx); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the original error; Commit closes the transaction.
	}()
	created, err := r.lockSecretsPreparation(ctx, tx, reservation)
	if err != nil {
		return err
	}
	stored, err := scanSecret(tx.QueryRow(ctx, `SELECT `+secretColumns+` FROM platform.project_secrets WHERE project_id=$1`, reservation.ProjectID), r.realm, reservation.ProjectID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if created {
			return domain.ErrConflict
		}
		payload, err := codec.Generate(binding)
		if err != nil {
			return err
		}
		stored, err = scanSecret(tx.QueryRow(ctx, `INSERT INTO platform.project_secrets(project_id,reservation_id,storage_target,database_oid,owner_oid,
			runtime_oid,schema_version,format_version,key_id,ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+secretColumns,
			binding.ProjectID, binding.ReservationID, binding.StorageTarget, binding.DatabaseOID, binding.OwnerOID, binding.RuntimeOID, binding.SchemaVersion,
			credentials.Version, codec.KeyID(), payload), r.realm, reservation.ProjectID)
		if err != nil {
			return catalogError(ctx, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE platform.project_preparations SET secrets_created=true WHERE project_id=$1`, reservation.ProjectID); err != nil {
			return catalogError(ctx, err)
		}
	case err != nil:
		return catalogError(ctx, err)
	case !created:
		return domain.ErrConflict
	}
	if stored.binding != binding {
		return domain.ErrConflict
	}
	if err := codec.Verify(binding, stored.version, stored.keyID, stored.payload); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return catalogError(ctx, err)
	}
	return nil
}

func (r *PreparationRepository) lockSecretsPreparation(ctx context.Context, tx pgx.Tx, reservation domain.PreparationReservation) (bool, error) {
	// Keep realm -> project -> preparation order, matching Reserve and lifecycle writers.
	var marker string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL FOR SHARE`, r.realm).Scan(&marker); err != nil {
		return false, catalogError(ctx, err)
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.projects WHERE id=$1 FOR SHARE`, reservation.ProjectID).Scan(&marker); err != nil {
		return false, catalogError(ctx, err)
	}
	// Authority and creation flag stay locked through the same commit as ciphertext.
	var created bool
	err := tx.QueryRow(ctx, `SELECT s.secrets_created `+currentPreparation+` FOR UPDATE OF s`,
		reservation.ProjectID, reservation.Version, reservation.Generation, r.target, reservation.ReservationID, reservation.OperationID, r.realm).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, domain.ErrConflict
	}
	if err != nil {
		return false, catalogError(ctx, err)
	}
	return created, nil
}
