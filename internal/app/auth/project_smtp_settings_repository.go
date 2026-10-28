package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type projectSMTPSettingsRepository struct{ profile *ProjectProfile }

func (s *projectSMTPSettingsRepository) use(ctx context.Context, operation func(context.Context, *settingspostgres.Repository) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p := s.profile
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := requireProjectCurrent(ctx, p.deps.Reader, p.key); err != nil {
			return err
		}
		if err := operation(ctx, settingspostgres.New(pool)); err != nil {
			return err
		}
		return requireProjectCurrent(ctx, p.deps.Reader, p.key)
	})
}

func (s *projectSMTPSettingsRepository) LoadSMTP(ctx context.Context) (settingsservice.SMTPStored, error) {
	var result settingsservice.SMTPStored
	err := s.use(ctx, func(ctx context.Context, repo *settingspostgres.Repository) error {
		var err error
		result, err = repo.LoadSMTP(ctx)
		return err
	})
	if err != nil {
		return settingsservice.SMTPStored{}, err
	}
	return result, nil
}

func (s *projectSMTPSettingsRepository) InitializeSMTP(ctx context.Context, seed settingsservice.SMTPStored) (settingsservice.SMTPStored, error) {
	var result settingsservice.SMTPStored
	err := s.use(ctx, func(ctx context.Context, repo *settingspostgres.Repository) error {
		var err error
		result, err = repo.InitializeSMTP(ctx, seed)
		return err
	})
	if err != nil {
		return settingsservice.SMTPStored{}, err
	}
	return result, nil
}

func (s *projectSMTPSettingsRepository) ReadSMTP(ctx context.Context, actor accessservice.Principal) (settingsdomain.SMTPSnapshot, error) {
	var result settingsdomain.SMTPSnapshot
	err := s.use(ctx, func(ctx context.Context, repo *settingspostgres.Repository) error {
		var err error
		result, err = repo.ReadSMTP(ctx, actor)
		return err
	})
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	return result, nil
}

func (s *projectSMTPSettingsRepository) UpdateSMTP(ctx context.Context, input settingsservice.SMTPUpdate) (settingsdomain.SMTPSnapshot, error) {
	var result settingsdomain.SMTPSnapshot
	err := s.use(ctx, func(ctx context.Context, repo *settingspostgres.Repository) error {
		var err error
		result, err = repo.UpdateSMTP(ctx, input)
		return err
	})
	if err != nil {
		return settingsdomain.SMTPSnapshot{}, err
	}
	return result, nil
}

func (s *projectSMTPSettingsRepository) AuthorizeSMTPTest(ctx context.Context, actor accessservice.Principal, version int64) (settingsservice.SMTPStored, error) {
	var result settingsservice.SMTPStored
	err := s.use(ctx, func(ctx context.Context, repo *settingspostgres.Repository) error {
		var err error
		result, err = repo.AuthorizeSMTPTest(ctx, actor, version)
		return err
	})
	if err != nil {
		return settingsservice.SMTPStored{}, err
	}
	return result, nil
}
