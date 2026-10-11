package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

func (cfg Config) Validate() error {
	checks := []func() error{
		cfg.validateLogger,
		cfg.Browser.Validate,
		func() error { return cfg.Account.Validate(cfg.Logger.Env == "prod") },
		func() error { return cfg.EmailChange.Validate(cfg.Logger.Env == "prod") },
		func() error { return cfg.Invitation.Validate(cfg.Logger.Env == "prod") },
		cfg.TemporaryPassword.Validate,
		cfg.Telegram.Validate,
		cfg.Retention.Validate,
		cfg.Capacity.Validate,
		cfg.HTTP.Validate,
		cfg.Server.Validate,
		cfg.Proxy.Validate,
		cfg.validatePorts,
		cfg.validateStorage,
		cfg.validateSessions,
		cfg.validateRecovery,
		cfg.validateDelivery,
		cfg.validateSwagger,
		cfg.validateProduction,
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (cfg Config) validateLogger() error {
	if cfg.Logger.Env != "dev" && cfg.Logger.Env != "test" && cfg.Logger.Env != "prod" {
		return fmt.Errorf("APP_ENV must be dev, test or prod")
	}
	if _, err := zapcore.ParseLevel(cfg.Logger.Level); err != nil {
		return fmt.Errorf("invalid LOG_LEVEL")
	}
	return nil
}

func (cfg Config) validatePorts() error {
	for key, value := range map[string]string{"PORT": cfg.Server.Port, "REDIS_PORT": cfg.Redis.Port, "SMTP_PORT": cfg.MailSender.SMTPPort} {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s must be a valid port", key)
		}
	}
	return nil
}

func (cfg Config) validateStorage() error {
	if cfg.Postgres.MaxConns < 1 || cfg.Postgres.MinConns < 0 || cfg.Postgres.MinConns > cfg.Postgres.MaxConns || cfg.Postgres.MaxConnLifetime <= 0 || cfg.Postgres.MaxConnIdleTime <= 0 {
		return fmt.Errorf("invalid PostgreSQL pool limits")
	}
	db, err := url.Parse(cfg.Postgres.URL)
	if err != nil || (db.Scheme != "postgres" && db.Scheme != "postgresql") || db.Hostname() == "" {
		return fmt.Errorf("invalid DATABASE_URL")
	}
	return nil
}

func (cfg Config) validateSessions() error {
	if cfg.Session.FreshAuthTTL < time.Minute || cfg.Session.FreshAuthTTL > 15*time.Minute {
		return fmt.Errorf("SESSION_FRESH_AUTH_TTL must be between 1m and 15m")
	}
	if cfg.Session.SessionTTL <= 0 || cfg.Session.AbsoluteSessionTTL < cfg.Session.SessionTTL || cfg.Session.SessionRefreshThreshold <= 0 || cfg.Session.SessionRefreshThreshold >= cfg.Session.SessionTTL {
		return fmt.Errorf("invalid session durations")
	}
	return nil
}

func (cfg Config) validateRecovery() error {
	if cfg.Password.ResetGlobalLimit < 1 {
		return fmt.Errorf("PASSWORD_RESET_GLOBAL_LIMIT must be positive")
	}
	if cfg.Password.ResetTokenTTL < time.Minute || cfg.Password.ResetTokenTTL > time.Hour {
		return fmt.Errorf("PASSWORD_RESET_TOKEN_TTL must be between 1m and 1h")
	}
	reset, err := url.Parse(cfg.Password.ResetURL)
	if err != nil || len(cfg.Password.ResetURL) > 2048 || reset.Hostname() == "" || reset.User != nil || reset.RawQuery != "" || reset.Fragment != "" || (reset.Scheme != "https" && reset.Scheme != "http") {
		return fmt.Errorf("invalid PASSWORD_RESET_URL")
	}
	return nil
}

func (cfg Config) validateDelivery() error {
	if strings.TrimSpace(cfg.Redis.Host) == "" || strings.TrimSpace(cfg.MailSender.SMTPHost) == "" {
		return fmt.Errorf("redis and SMTP hosts are required")
	}
	if _, err := mail.ParseAddress(cfg.MailSender.SMTPFrom); err != nil || strings.ContainsAny(cfg.MailSender.SMTPFrom, "\r\n") {
		return fmt.Errorf("invalid SMTP_FROM")
	}
	if cfg.MailSender.SMTPDomain == "" || strings.ContainsAny(cfg.MailSender.SMTPDomain, "\r\n <>@") {
		return fmt.Errorf("invalid SMTP_DOMAIN")
	}
	return nil
}

func (cfg Config) validateSwagger() error {
	if cfg.Swagger.Enabled && (cfg.Swagger.Username == "" || cfg.Swagger.Password == "") {
		return fmt.Errorf("swagger credentials required when enabled")
	}
	return nil
}

func (cfg Config) validateProduction() error {
	if cfg.Logger.Env == "prod" {
		if !cfg.MailSender.RequireTLS {
			return fmt.Errorf("production verification delivery requires SMTP_REQUIRE_TLS")
		}
		if !strings.HasPrefix(cfg.Password.ResetURL, "https:") {
			return fmt.Errorf("production reset URL must use HTTPS")
		}
		if len(cfg.Redis.Password) < 16 || cfg.Redis.Password == "change-me" {
			return fmt.Errorf("production Redis password must have at least 16 characters")
		}
		if cfg.Swagger.Enabled && len(cfg.Swagger.Password) < 16 {
			return fmt.Errorf("production Swagger password must have at least 16 characters")
		}
	}
	return nil
}
