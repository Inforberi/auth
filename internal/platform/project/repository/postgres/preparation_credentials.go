package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// ReadDatabaseCredential returns only committed, current provisioning material; it never creates it.
func (r *PreparationRepository) ReadDatabaseCredential(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) (credentials.DatabaseCredential, error) {
	var empty credentials.DatabaseCredential
	if codec == nil || !r.matchesSecretsBinding(reservation, binding) {
		return empty, domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.CheckRuntime(ctx); err != nil {
		return empty, err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return empty, catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Never return plaintext on a failed commit.
	}()
	created, err := r.lockSecretsPreparation(ctx, tx, reservation)
	if err != nil {
		return empty, err
	}
	if !created {
		return empty, domain.ErrConflict
	}
	stored, err := scanSecret(tx.QueryRow(ctx, `SELECT `+secretColumns+` FROM platform.project_secrets WHERE project_id=$1`, reservation.ProjectID), r.realm, reservation.ProjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, domain.ErrConflict
	}
	if err != nil {
		return empty, catalogError(ctx, err)
	}
	if stored.binding != binding {
		return empty, domain.ErrConflict
	}
	value, err := codec.OpenDatabase(binding, stored.version, stored.keyID, stored.payload)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, catalogError(ctx, err)
	}
	return value, nil
}
