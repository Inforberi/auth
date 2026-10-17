package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

const providerColumns = `provider,version,client_id,secret_set`

func scanProvider(row pgx.Row, secret bool) (service.ProviderStored, error) {
	var result service.ProviderStored
	values := []any{&result.Provider, &result.Version, &result.ClientID, &result.SecretSet}
	if secret {
		values = append(values, &result.Secret)
	}
	err := row.Scan(values...)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, domain.ErrNotInitialized
	}
	return result, err
}

func (r *Repository) LoadProvider(ctx context.Context, name string) (service.ProviderStored, error) {
	return scanProvider(r.db.QueryRow(ctx, `SELECT `+providerColumns+`,secret FROM auth.provider_settings WHERE provider=$1`, name), true)
}

func (r *Repository) ReadProvider(ctx context.Context, actor accessservice.Principal, name string) (domain.ProviderSnapshot, error) {
	stored, err := scanProvider(r.db.QueryRow(ctx, `SELECT `+providerColumns+` FROM auth.provider_settings WHERE provider=$4 AND `+settingsReadGuard,
		actor.UserID, actor.TokenHash, settings.AuthSettingsManage, name), false)
	if errors.Is(err, domain.ErrNotInitialized) {
		return domain.ProviderSnapshot{}, accessdomain.ErrForbidden
	}
	return stored.ProviderSnapshot, err
}

func (r *Repository) InitializeProvider(ctx context.Context, seed service.ProviderStored) (service.ProviderStored, error) {
	var result service.ProviderStored
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		stored, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+`,secret FROM auth.provider_settings WHERE provider=$1 FOR UPDATE`, seed.Provider), true)
		if err == nil {
			result = stored
			return nil
		}
		if !errors.Is(err, domain.ErrNotInitialized) {
			return err
		}
		var initialized bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)`).Scan(&initialized); err != nil {
			return err
		}
		if initialized {
			return domain.ErrNotInitialized
		}
		result, err = scanProvider(tx.QueryRow(ctx, `INSERT INTO auth.provider_settings(provider,client_id,secret,secret_set)
			VALUES($1,$2,$3,$4) RETURNING `+providerColumns+`,secret`, seed.Provider, seed.ClientID, seed.Secret, seed.SecretSet), true)
		return err
	})
	return result, err
}
