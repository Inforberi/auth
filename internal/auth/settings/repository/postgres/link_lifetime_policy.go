package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func LoadRegistrationLinkLifetime(ctx context.Context, tx pgx.Tx) (domain.LinkLifetimePolicy, error) {
	return loadPolicy[domain.LinkLifetimePolicy](ctx, tx, linkLifetimePolicyTable)
}

func (r *Repository) LinkLifetimePolicy() VersionedPolicy[domain.LinkLifetimePolicy] {
	return VersionedPolicy[domain.LinkLifetimePolicy]{repo: r, table: linkLifetimePolicyTable}
}

func LoadRegistrationFrontend(ctx context.Context, tx pgx.Tx) (domain.FrontendPolicy, error) {
	return loadPolicy[domain.FrontendPolicy](ctx, tx, frontendPolicyTable)
}
