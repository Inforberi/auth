package postgres

import (
	"context"
	"errors"

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

func ProjectLinkLifetime(ctx context.Context, db policyReader, baseline domain.LinkLifetimePolicy, resendSeconds int64) (domain.LinkLifetimePolicy, error) {
	var installed bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('auth.link_lifetime_policy') IS NOT NULL`).Scan(&installed); err != nil {
		return domain.LinkLifetimePolicy{}, err
	}
	if !installed {
		return baseline, nil
	}
	var stored *domain.LinkLifetimePolicy
	err := db.QueryRow(ctx, `SELECT p.policy FROM auth.link_lifetime_policy p
		JOIN auth.settings_source s ON s.singleton=p.singleton WHERE p.singleton AND s.mode='api'`).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return baseline, nil
	}
	if err != nil {
		return domain.LinkLifetimePolicy{}, err
	}
	if stored == nil {
		return baseline, nil
	}
	return *stored, stored.Validate(resendSeconds)
}

func ProjectFrontend(ctx context.Context, db policyReader, baseline domain.FrontendPolicy) (domain.FrontendPolicy, error) {
	var installed bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('auth.frontend_policy') IS NOT NULL`).Scan(&installed); err != nil || !installed {
		return baseline, err
	}
	var stored *domain.FrontendPolicy
	err := db.QueryRow(ctx, `SELECT CASE WHEN s.mode='api' THEN p.policy END FROM auth.frontend_policy p
		JOIN auth.settings_source s ON s.singleton=p.singleton WHERE p.singleton`).Scan(&stored)
	if err != nil || stored == nil {
		return baseline, err
	}
	return *stored, nil
}
