package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// Follows user and public policy locks. A current row rejects unversioned legacy proofs.
func RequireProviderRevision(ctx context.Context, tx pgx.Tx, issuer string, version int64) error {
	name := domain.PrimaryMethod("oidc", issuer)
	if name == "" {
		return domain.ErrProviderRevision
	}
	var current int64
	var ready bool
	err := tx.QueryRow(ctx, `SELECT version,client_id<>'' AND secret_set FROM auth.provider_settings WHERE provider=$1 FOR SHARE`, name).Scan(&current, &ready)
	// Trusted static adapters have no managed row. Production startup seeds both rows;
	// managed proofs must fail closed when a row is missing, even after data loss.
	if errors.Is(err, pgx.ErrNoRows) && version == 0 {
		var unmanaged bool
		if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.provider_settings)
			AND NOT EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)`).Scan(&unmanaged); err != nil {
			return err
		}
		if unmanaged {
			return nil
		}
		return domain.ErrProviderRevision
	}
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!ready || version <= 0 || version != current) {
		return domain.ErrProviderRevision
	}
	return err
}
