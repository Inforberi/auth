package auth

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (s realmSecurity) assembleSMTP(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*mailer.Mailer, *settingssmtphttp.SMTPHandler, error) {
	cipher, err := s.cipher(cfg.Account.EncryptionKey, "smtp-settings:v1")
	if err != nil {
		return nil, nil, err
	}
	allowed := strings.Split(cfg.SMTPAllowedTargets, ",")
	if strings.TrimSpace(cfg.SMTPAllowedTargets) == "" {
		allowed = []string{net.JoinHostPort(cfg.MailSender.SMTPHost, cfg.MailSender.SMTPPort)}
	}
	limits, err := settingsredis.NewSMTPScoped(rdb, s.scope)
	if err != nil {
		return nil, nil, err
	}
	svc, err := settingssmtp.NewSMTP(settingspostgres.New(pool), cipher,
		func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
			return mailer.CheckContext(ctx, projectapp.MailConfig(c, password))
		}, limits, allowed, cfg.Logger.Env == "prod")
	if err != nil {
		return nil, nil, err
	}
	port, err := strconv.Atoi(cfg.MailSender.SMTPPort)
	if err != nil {
		return nil, nil, settingsdomain.ErrInvalidSMTP
	}
	initial := settingsdomain.SMTPConfig{
		Host: cfg.MailSender.SMTPHost, Port: port, Username: cfg.MailSender.SMTPUsername,
		From: cfg.MailSender.SMTPFrom, Domain: cfg.MailSender.SMTPDomain, RequireTLS: cfg.MailSender.RequireTLS,
	}
	if err := svc.Initialize(ctx, initial, cfg.MailSender.SMTPPassword); err != nil {
		return nil, nil, err
	}
	mail := mailer.NewWithSource(func(ctx context.Context) (mailer.Config, error) {
		c, password, err := svc.Credentials(ctx)
		if err != nil {
			return mailer.Config{}, err
		}
		return projectapp.MailConfig(c, password), nil
	})
	return mail, settingssmtphttp.NewSMTP(svc, log), nil
}
