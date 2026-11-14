package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
)

func (r *Repository) synchronizeEnvironment(ctx context.Context, tx pgx.Tx, input configuration.Prepared, previous map[string]string, initialized bool) error {
	changed := func(name string) bool { return !initialized || previous[name] != input.ComponentHashes[name] }
	for _, p := range input.Providers {
		if changed(p.Provider) {
			if err := synchronizeProvider(ctx, tx, p, initialized); err != nil {
				return err
			}
		}
	}
	if changed("smtp") {
		if initialized {
			if _, err := scanSMTP(tx.QueryRow(ctx, `SELECT `+smtpColumns+` FROM auth.smtp_settings WHERE singleton FOR UPDATE`), false); err != nil {
				return err
			}
		}
		p := input.SMTP
		if _, err := tx.Exec(ctx, `INSERT INTO auth.smtp_settings(singleton,configuration,password,password_set) VALUES(true,$1,$2,$3)
		ON CONFLICT(singleton) DO UPDATE SET version=auth.smtp_settings.version+1,configuration=EXCLUDED.configuration,password=EXCLUDED.password,password_set=EXCLUDED.password_set`, p.Config, p.Password, p.PasswordSet); err != nil {
			return err
		}
	}
	if changed("retention") {
		if initialized {
			before, err := scanRetention(tx.QueryRow(ctx, `SELECT `+retentionColumns+` FROM auth.retention_settings WHERE singleton FOR UPDATE`))
			if err != nil {
				return err
			}
			// ENV changes require an explicit maintenance restart; retain the same irreversible-cleanup acknowledgement.
			if input.Retention.Shortens(before.Policy) && !input.ConfirmRetentionShortening {
				return domain.ErrRetentionConfirmation
			}
		}
		p := input.Retention
		if _, err := tx.Exec(ctx, `INSERT INTO auth.retention_settings(singleton,email_reservation_days,session_days,security_audit_days) VALUES(true,$1,$2,$3)
		ON CONFLICT(singleton) DO UPDATE SET version=auth.retention_settings.version+1,email_reservation_days=EXCLUDED.email_reservation_days,session_days=EXCLUDED.session_days,security_audit_days=EXCLUDED.security_audit_days`, p.EmailReservationDays, p.SessionDays, p.SecurityAuditDays); err != nil {
			return err
		}
	}
	if !changed("policy") {
		return nil
	}
	return synchronizePolicy(ctx, tx, input.Policy, initialized)
}

func synchronizePolicy(ctx context.Context, tx pgx.Tx, policy domain.Policy, initialized bool) error {
	before, err := LockPolicyInTransaction(ctx, tx)
	if errors.Is(err, domain.ErrNotInitialized) && !initialized {
		_, err = InitializeInTransaction(ctx, tx, policy)
		return err
	}
	if err != nil {
		return err
	}
	if policy.RestrictsLogin(before.Policy) {
		if err := accesspostgres.RequireUsableAdministrator(ctx, tx); err != nil {
			return err
		}
	}
	if err := checkStoredPolicyDependencies(ctx, tx, policy, true); err != nil {
		return err
	}
	if before.Policy == policy {
		return nil
	}
	_, err = ApplyPolicyChange(ctx, tx, policy)
	return err
}

func synchronizeProvider(ctx context.Context, tx pgx.Tx, p providers.ProviderStored, initialized bool) error {
	before, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM auth.provider_settings WHERE provider=$1 FOR UPDATE`, p.Provider), false)
	if err != nil && (initialized || !errors.Is(err, domain.ErrNotInitialized)) {
		return err
	}
	if before.ClientID != "" && before.ClientID != p.ClientID {
		var bound bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.linked_identities WHERE issuer=$1)`, domain.ProviderIssuer(p.Provider)).Scan(&bound); err != nil {
			return err
		}
		if bound {
			return domain.ErrProviderClientBound
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.provider_settings(provider,client_id,secret,secret_set) VALUES($1,$2,$3,$4)
	ON CONFLICT(provider) DO UPDATE SET version=auth.provider_settings.version+1,client_id=EXCLUDED.client_id,secret=EXCLUDED.secret,secret_set=EXCLUDED.secret_set`, p.Provider, p.ClientID, p.Secret, p.SecretSet)
	return err
}
