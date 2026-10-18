package auth

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsredis "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/redis"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (s realmSecurity) assembleSMTP(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, cfg *config.Config, log *zap.Logger) (*mailer.Mailer, *settingshttp.SMTPHandler, error) {
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
	svc, err := settingsservice.NewSMTP(settingspostgres.New(pool), cipher,
		func(ctx context.Context, c settingsdomain.SMTPConfig, password string) error {
			return mailer.CheckContext(ctx, smtpMailerConfig(c, password))
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
		return smtpMailerConfig(c, password), nil
	})
	return mail, settingshttp.NewSMTP(svc, log), nil
}

func smtpMailerConfig(c settingsdomain.SMTPConfig, password string) mailer.Config {
	return mailer.Config{
		SMTPHost: c.Host, SMTPPort: strconv.Itoa(c.Port), SMTPUsername: c.Username,
		SMTPPassword: password, SMTPFrom: c.From, SMTPDomain: c.Domain, RequireTLS: c.RequireTLS,
	}
}
