package postgres

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) CredentialLifetimePolicy() VersionedPolicy[domain.CredentialLifetimePolicy] {
	return VersionedPolicy[domain.CredentialLifetimePolicy]{repo: r, table: credentialLifetimePolicyTable}
}

func ProjectFreshAuth(ctx context.Context, db policyReader, baseline time.Duration) (time.Duration, error) {
	policy, err := ProjectCredentialLifetime(ctx, db)
	if policy.FreshAuthSeconds == 0 {
		return baseline, err
	}
	return time.Duration(policy.FreshAuthSeconds) * time.Second, err
}

func ProjectCredentialLifetime(ctx context.Context, db policyReader) (domain.CredentialLifetimePolicy, error) {
	var result domain.CredentialLifetimePolicy
	var installed bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('auth.credential_lifetime_policy') IS NOT NULL`).Scan(&installed); err != nil || !installed {
		return result, err
	}
	var stored *domain.CredentialLifetimePolicy
	err := db.QueryRow(ctx, `SELECT CASE WHEN s.mode='api' THEN p.policy END FROM auth.credential_lifetime_policy p
		JOIN auth.settings_source s ON s.singleton=p.singleton WHERE p.singleton`).Scan(&stored)
	if err != nil || stored == nil {
		return result, err
	}
	return *stored, stored.Validate()
}
