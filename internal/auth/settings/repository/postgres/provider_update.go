package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *Repository) UpdateProvider(ctx context.Context, input service.ProviderUpdate) (domain.ProviderSnapshot, error) {
	var result domain.ProviderSnapshot
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, "", settings.AuthSettingsManage); err != nil {
			return err
		}
		policy, err := LockPublicPolicy(ctx, tx)
		if err != nil {
			return err
		}
		before, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+`,secret FROM auth.provider_settings WHERE provider=$1 FOR UPDATE`, input.Provider), true)
		if err != nil {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrPolicyConflict
		}
		enabled := input.Provider == "google" && policy.Methods.Google || input.Provider == "telegram" && policy.Methods.Telegram
		secret, secretSet, err := providerReplacement(before, input, enabled)
		if err != nil {
			return err
		}
		if before.ClientID != input.ClientID {
			var bound bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.linked_identities WHERE issuer=$1)`, domain.ProviderIssuer(input.Provider)).Scan(&bound); err != nil {
				return err
			}
			if bound {
				return domain.ErrProviderClientBound
			}
		}
		if input.Secret == nil && before.ClientID == input.ClientID {
			result = before.ProviderSnapshot
			return nil
		}
		stored, err := scanProvider(tx.QueryRow(ctx, `UPDATE auth.provider_settings SET version=version+1,client_id=$2,secret=$3,secret_set=$4
			WHERE provider=$1 RETURNING `+providerColumns, input.Provider, input.ClientID, secret, secretSet), false)
		if err != nil {
			return err
		}
		result = stored.ProviderSnapshot
		_, err = tx.Exec(ctx, `INSERT INTO auth.provider_settings_audit(actor_id,provider,version,previous_configuration,next_configuration)
			VALUES($1,$2,$3,$4,$5)`, input.Actor.UserID, input.Provider, result.Version, before.ProviderSnapshot, result)
		return err
	})
	return result, err
}

func providerReplacement(before service.ProviderStored, input service.ProviderUpdate, enabled bool) ([]byte, bool, error) {
	secret, set := input.Secret, input.SecretSet
	if secret == nil {
		if before.ClientID != input.ClientID {
			return nil, false, domain.ErrInvalidProvider
		}
		secret, set = before.Secret, before.SecretSet
	}
	if enabled && (!set || input.ClientID == "" || before.ClientID != input.ClientID) {
		return nil, false, domain.ErrMethodNotReady
	}
	if set && input.ClientID == "" {
		return nil, false, domain.ErrInvalidProvider
	}
	return secret, set, nil
}

// Access mutations serialize this readiness read with credential changes.
func requireProviderSettings(ctx context.Context, tx pgx.Tx, policy domain.Policy) error {
	var ready bool
	err := tx.QueryRow(ctx, `SELECT CASE WHEN EXISTS(SELECT 1 FROM auth.provider_settings)
		OR EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)
		THEN (NOT $1 OR EXISTS(SELECT 1 FROM auth.provider_settings WHERE provider='google' AND client_id<>'' AND secret_set))
		AND (NOT $2 OR EXISTS(SELECT 1 FROM auth.provider_settings WHERE provider='telegram' AND client_id<>'' AND secret_set))
		ELSE true END`, policy.Methods.Google, policy.Methods.Telegram).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return domain.ErrMethodNotReady
	}
	return nil
}
