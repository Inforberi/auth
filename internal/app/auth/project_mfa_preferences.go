package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type projectMFAPreferences struct{ manager *projectMFA }

func (p projectMFAPreferences) service(pool *pgxpool.Pool) (*mfamanagement.Preferences, error) {
	f := p.manager.factory
	return mfamanagement.NewPreferences(mfapostgres.New(pool), f.cipher, f.limits, mfamanagement.PreferenceConfig{UserChangesPerMinute: f.managementConfig.UserLimitPerMinute, ProjectChangesPerMinute: f.managementConfig.GlobalLimitPerMinute})
}

func (p projectMFAPreferences) Read(ctx context.Context, proof mfaservice.Proof) (domain.Preference, error) {
	var result domain.Preference
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

func (p projectMFAPreferences) Update(ctx context.Context, input mfamanagement.PreferenceUpdate) (domain.Preference, error) {
	var result domain.Preference
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
