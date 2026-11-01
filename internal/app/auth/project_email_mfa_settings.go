package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type projectEmailMFASettings struct{ profile *ProjectProfile }

func (s projectEmailMFASettings) use(ctx context.Context, checkReadiness bool, operation func(context.Context, *settingsservice.EmailMFA) (settingsdomain.EmailMFASnapshot, error)) (settingsdomain.EmailMFASnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	var result settingsdomain.EmailMFASnapshot
	err := p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		var err error
		ready := p.emailMFA != nil && p.deliveryReady()
		if checkReadiness && ready {
			_, smtpErr := p.emailMFA.mail.smtp.credentialsInPool(ctx, pool)
			ready = smtpErr == nil && mfapostgres.New(pool).CheckRecoveryOperator(ctx) == nil
		}
		result, err = operation(ctx, settingsservice.NewEmailMFA(settingspostgres.New(pool), ready))
		if err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
	if err != nil {
		return settingsdomain.EmailMFASnapshot{}, err
	}
	return result, nil
}

func (s projectEmailMFASettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.EmailMFASnapshot, error) {
	return s.use(ctx, false, func(ctx context.Context, service *settingsservice.EmailMFA) (settingsdomain.EmailMFASnapshot, error) {
		return service.Read(ctx, actor)
	})
}

func (s projectEmailMFASettings) Update(ctx context.Context, input settingsservice.EmailMFAUpdate) (settingsdomain.EmailMFASnapshot, error) {
	return s.use(ctx, input.Allowed, func(ctx context.Context, service *settingsservice.EmailMFA) (settingsdomain.EmailMFASnapshot, error) {
		return service.Update(ctx, input)
	})
}
