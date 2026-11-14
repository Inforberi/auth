package settings

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func AssembleConfiguration(ctx context.Context, scope realmscope.Scope, pool *pgxpool.Pool, cfg *config.Config) (configuration.Lease, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if pool.Config().MaxConns < 2 {
		return nil, domain.ErrSourceConflict
	}
	input := configuration.Input{Mode: cfg.SettingsSource.Mode, ConfirmRetentionShortening: cfg.SettingsSource.ConfirmRetentionShortening}
	repo := settingspostgres.New(pool)
	if input.Mode.Effective() == domain.SourceAPI {
		return configuration.Start(ctx, repo, input, "", nil, nil)
	}
	input.Policy = cfg.InitialAuthPolicy()
	validation := *cfg
	if err := validation.ConfigureAuthAdapters(input.Policy); err != nil {
		return nil, err
	}
	input.Retention = domain.RetentionPolicy{EmailReservationDays: cfg.Retention.EmailReservationDays, SessionDays: cfg.Retention.SessionDays, SecurityAuditDays: cfg.Retention.SecurityAuditDays}
	port, err := strconv.Atoi(cfg.MailSender.SMTPPort)
	if err != nil {
		return nil, domain.ErrInvalidSMTP
	}
	input.SMTP = domain.SMTPConfig{Host: cfg.MailSender.SMTPHost, Port: port, Username: cfg.MailSender.SMTPUsername, From: cfg.MailSender.SMTPFrom, Domain: cfg.MailSender.SMTPDomain, RequireTLS: cfg.MailSender.RequireTLS}
	input.SMTPPassword = cfg.MailSender.SMTPPassword
	input.RequireTLS = cfg.Logger.Env == "prod"
	input.AllowedSMTP = strings.Split(cfg.SMTPAllowedTargets, ",")
	if strings.TrimSpace(cfg.SMTPAllowedTargets) == "" {
		input.AllowedSMTP = []string{net.JoinHostPort(cfg.MailSender.SMTPHost, cfg.MailSender.SMTPPort)}
	}
	input.Providers = [2]configuration.ProviderInput{{Name: "google", ClientID: cfg.Google.ClientID, Secret: cfg.Google.ClientSecret}, {Name: "telegram", ClientID: cfg.Telegram.ClientID, Secret: cfg.Telegram.ClientSecret}}
	ciphers := make(map[string]settingsservice.ProviderCipher)
	for _, name := range []string{"google", "telegram", "smtp-settings"} {
		purpose := "provider-" + name + ":v1"
		if name == "smtp-settings" {
			purpose = name + ":v1"
		}
		cipher, err := secretbox.ForScope(scope, cfg.Account.EncryptionKey, purpose)
		if err != nil {
			return nil, err
		}
		ciphers[name] = cipher
	}
	return configuration.Start(ctx, repo, input, cfg.Account.EncryptionKey, ciphers["smtp-settings"], ciphers)
}
