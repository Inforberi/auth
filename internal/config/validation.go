package config

import (
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap/zapcore"
)

func (cfg Config) Validate() error {
	if cfg.Logger.Env != "dev" && cfg.Logger.Env != "test" && cfg.Logger.Env != "prod" {
		return fmt.Errorf("APP_ENV must be dev, test or prod")
	}
	if _, err := zapcore.ParseLevel(cfg.Logger.Level); err != nil {
		return fmt.Errorf("invalid LOG_LEVEL")
	}
	if err := cfg.Account.Validate(cfg.Logger.Env == "prod"); err != nil {
		return err
	}
	if err := cfg.validatePorts(); err != nil {
		return err
	}
	return cfg.validateStorage()
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
	if cfg.Session.SessionTTL <= 0 || cfg.Session.AbsoluteSessionTTL < cfg.Session.SessionTTL || cfg.Session.SessionRefreshThreshold <= 0 || cfg.Session.SessionRefreshThreshold >= cfg.Session.SessionTTL {
		return fmt.Errorf("invalid session durations")
	}
	return cfg.validateIdentity()
}

func (cfg Config) validateIdentity() error {
	if cfg.Password.ResetTokenTTL <= 0 {
		return fmt.Errorf("PASSWORD_RESET_TOKEN_TTL must be positive")
	}
	reset, err := url.Parse(cfg.Password.ResetURL)
	if err != nil || reset.Hostname() == "" || reset.User != nil || reset.Fragment != "" || (reset.Scheme != "https" && reset.Scheme != "http") {
		return fmt.Errorf("invalid PASSWORD_RESET_URL")
	}
	if strings.TrimSpace(cfg.Redis.Host) == "" || strings.TrimSpace(cfg.MailSender.SMTPHost) == "" {
		return fmt.Errorf("redis and SMTP hosts are required")
	}
	if _, err := mail.ParseAddress(cfg.MailSender.SMTPFrom); err != nil || strings.ContainsAny(cfg.MailSender.SMTPFrom, "\r\n") {
		return fmt.Errorf("invalid SMTP_FROM")
	}
	if cfg.MailSender.SMTPDomain == "" || strings.ContainsAny(cfg.MailSender.SMTPDomain, "\r\n <>@") {
		return fmt.Errorf("invalid SMTP_DOMAIN")
	}
	if cfg.Swagger.Enabled && (cfg.Swagger.Username == "" || cfg.Swagger.Password == "") {
		return fmt.Errorf("swagger credentials required when enabled")
	}
	return cfg.validateProduction(reset)
}

func (cfg Config) validateProduction(reset *url.URL) error {
	if cfg.Logger.Env == "prod" {
		if !cfg.MailSender.RequireTLS {
			return fmt.Errorf("production verification delivery requires SMTP_REQUIRE_TLS")
		}
		if reset.Scheme != "https" {
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
