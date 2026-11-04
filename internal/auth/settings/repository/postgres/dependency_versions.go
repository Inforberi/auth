package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func checkDependencyVersions(ctx context.Context, tx pgx.Tx, next domain.Policy, versions domain.DependencyVersions) error {
	for _, dependency := range []struct {
		selected bool
		query    string
		version  int64
	}{
		{next.RequiresEmailDelivery(), `SELECT version FROM auth.smtp_settings WHERE singleton FOR SHARE`, versions.SMTP},
		{next.Methods.Google, `SELECT version FROM auth.provider_settings WHERE provider='google' FOR SHARE`, versions.Google},
		{next.Methods.Telegram, `SELECT version FROM auth.provider_settings WHERE provider='telegram' FOR SHARE`, versions.Telegram},
	} {
		if !dependency.selected {
			continue
		}
		var current int64
		err := tx.QueryRow(ctx, dependency.query).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrMethodNotReady
		}
		if err != nil {
			return err
		}
		if current != dependency.version {
			return domain.ErrPolicyConflict
		}
	}
	return nil
}

// DependencyVersions reads the readiness dependencies in one statement snapshot.
// Missing settings retain version zero; storage/context errors are returned as-is.
func (r *Repository) DependencyVersions(ctx context.Context) (domain.DependencyVersions, error) {
	var versions domain.DependencyVersions
	err := r.db.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM auth.smtp_settings WHERE singleton),0),
   COALESCE((SELECT version FROM auth.provider_settings WHERE provider='google'),0),
   COALESCE((SELECT version FROM auth.provider_settings WHERE provider='telegram'),0)`).Scan(&versions.SMTP, &versions.Google, &versions.Telegram)
	return versions, err
}
