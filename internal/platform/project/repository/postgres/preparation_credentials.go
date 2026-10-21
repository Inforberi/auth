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
	var value credentials.DatabaseCredential
	err := r.readSecrets(ctx, reservation, binding, codec, func(stored secretRecord) error {
		var err error
		value, err = codec.OpenDatabase(binding, stored.version, stored.keyID, stored.payload)
		return err
	})
	if err != nil {
		return credentials.DatabaseCredential{}, err
	}
	return value, nil
}

func (r *PreparationRepository) ReadSetupProof(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) (credentials.SetupProof, error) {
	var value credentials.SetupProof
	err := r.readSecrets(ctx, reservation, binding, codec, func(stored secretRecord) error {
		var err error
		value, err = codec.OpenSetup(binding, stored.version, stored.keyID, stored.payload)
		return err
	})
	if err != nil {
		return credentials.SetupProof{}, err
	}
	return value, nil
}

func (r *PreparationRepository) ReadOnboardingKeys(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) (credentials.OnboardingKeys, error) {
	var value credentials.OnboardingKeys
	err := r.readSecrets(ctx, reservation, binding, codec, func(stored secretRecord) error {
		var err error
		value, err = codec.OpenOnboarding(binding, stored.version, stored.keyID, stored.payload)
		return err
	})
	if err != nil {
		return credentials.OnboardingKeys{}, err
	}
	return value, nil
}

func (r *PreparationRepository) readSecrets(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, decode func(secretRecord) error) error {
	if codec == nil || !r.matchesSecretsBinding(reservation, binding) {
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
		_ = tx.Rollback(cleanup) //nolint:gosec // Never return plaintext on a failed commit.
	}()
	created, err := r.lockSecretsPreparation(ctx, tx, reservation)
	if err != nil {
		return err
	}
	if !created {
		return domain.ErrConflict
	}
	stored, err := scanSecret(tx.QueryRow(ctx, `SELECT `+secretColumns+` FROM platform.project_secrets WHERE project_id=$1`, reservation.ProjectID), r.realm, reservation.ProjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	if err != nil {
		return catalogError(ctx, err)
	}
	if stored.binding != binding {
		return domain.ErrConflict
	}
	if err := decode(stored); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return catalogError(ctx, err)
	}
	return nil
}
