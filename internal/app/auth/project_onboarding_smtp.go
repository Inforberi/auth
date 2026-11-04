package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (s realmSecurity) projectOnboardingSMTP(ctx context.Context, root string, pool *pgxpool.Pool, rdb *redis.Client, allowed []string) (*mailer.Mailer, error) {
	cipher, err := s.cipher(root, "smtp-settings:v1")
	if err != nil {
		return nil, err
	}
	limits, err := settingsredis.NewSMTPScoped(rdb, s.scope)
	if err != nil {
		return nil, err
	}
	svc, err := settingssmtp.NewSMTP(settingspostgres.New(pool), cipher,
		func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
			return mailer.CheckContext(ctx, smtpMailerConfig(c, password))
		}, limits, allowed, true)
	if err != nil {
		return nil, err
	}
	if _, _, err := svc.Credentials(ctx); err != nil {
		return nil, err
	}
	return mailer.NewWithSource(func(ctx context.Context) (mailer.Config, error) {
		c, password, err := svc.Credentials(ctx)
		if err != nil {
			return mailer.Config{}, err
		}
		return smtpMailerConfig(c, password), nil
	}), nil
}
