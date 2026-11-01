package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type projectMFAPreferences struct{ manager *projectMFA }

func (p projectMFAPreferences) service(pool *pgxpool.Pool) (*mfaservice.Preferences, error) {
	f := p.manager.factory
	return mfaservice.NewPreferences(mfapostgres.New(pool), f.cipher, f.limits, mfaservice.PreferenceConfig{UserChangesPerMinute: f.managementConfig.UserLimitPerMinute, ProjectChangesPerMinute: f.managementConfig.GlobalLimitPerMinute})
}

func (p projectMFAPreferences) Read(ctx context.Context, proof mfaservice.Proof) (mfadomain.Preference, error) {
	var result mfadomain.Preference
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		s, err := p.service(pool)
		if err != nil {
			return err
		}
		result, err = s.Read(ctx, proof)
		return err
	})
	return result, err
}

func (p projectMFAPreferences) Update(ctx context.Context, input mfaservice.PreferenceUpdate) (mfadomain.Preference, error) {
	var result mfadomain.Preference
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		s, err := p.service(pool)
		if err != nil {
			return err
		}
		result, err = s.Update(ctx, input)
		return err
	})
	return result, err
}
