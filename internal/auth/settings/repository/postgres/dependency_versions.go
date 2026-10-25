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
