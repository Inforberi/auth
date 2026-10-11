package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/server/http"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func validConfig() Config {
	return Config{
		HTTP:      requestmiddleware.CapacityConfig{MaxInFlight: 128, RequestTimeout: 10 * time.Second},
		Browser:   requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://localhost:8443"}},
		Account:   accountservice.Config{URL: "https://example.com/verify-email", EncryptionKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100},
		Retention: accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100, Interval: time.Minute},
		Postgres:  postgres.Config{URL: "postgres://app:secret@localhost/app", MaxConns: 10, MinConns: 2, MaxConnLifetime: time.Hour, MaxConnIdleTime: time.Minute},
		Server:    httpserver.Config{Port: "8080"}, Logger: logger.Config{Env: "dev", Level: "info"},
		Redis:      redisclient.Config{Host: "localhost", Port: "6379"},
		MailSender: mailer.Config{SMTPHost: "localhost", SMTPPort: "1025", SMTPFrom: "auth@example.com", SMTPDomain: "example.com"},
		Session:    sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute},
		Password:   passwordservice.Config{ResetTokenTTL: time.Hour, ResetURL: "https://example.com/reset", ResetGlobalLimit: 100},
		Capacity:   passwordservice.CapacityConfig{HashConcurrency: 2, LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 1000},
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"port":            func(c *Config) { c.Server.Port = "0" },
		"origins":         func(c *Config) { c.Browser.AllowedOrigins = nil },
		"retention":       func(c *Config) { c.Retention.SecurityAuditDays = 0 },
		"pool":            func(c *Config) { c.Postgres.MinConns = 11 },
		"absolute":        func(c *Config) { c.Session.AbsoluteSessionTTL = time.Minute },
		"threshold":       func(c *Config) { c.Session.SessionRefreshThreshold = c.Session.SessionTTL },
		"fresh auth":      func(c *Config) { c.Session.FreshAuthTTL = 0 },
		"long fresh auth": func(c *Config) { c.Session.FreshAuthTTL = 16 * time.Minute },
		"secretURL":       func(c *Config) { c.Password.ResetURL = "https://user:password@example.com/reset" },
		"swagger":         func(c *Config) { c.Swagger.Enabled = true },
		"production":      func(c *Config) { c.Logger.Env = "prod" },
		"header":          func(c *Config) { c.MailSender.SMTPFrom = "test@example.com\r\nBcc: victim@example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestBrowserOriginEnvironment(t *testing.T) {
	t.Setenv("AUTH_ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com")
	var cfg requestmiddleware.OriginConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedOrigins) != 2 || cfg.AllowedOrigins[0] != "https://app.example.com" || cfg.AllowedOrigins[1] != "https://admin.example.com" {
		t.Fatal("origin list parsed incorrectly")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSeparateSessionEnvironment(t *testing.T) {
	t.Setenv("SESSION_FRESH_AUTH_TTL", "3m")
	t.Setenv("SESSION_TTL", "2h")
	t.Setenv("ABSOLUTE_SESSION_TTL", "5h")
	// Test the exact configuration tags used by startup, without real secrets.
	var cfg sessionservice.Config
	if err := readSession(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 2*time.Hour || cfg.AbsoluteSessionTTL != 5*time.Hour || cfg.FreshAuthTTL != 3*time.Minute {
		t.Fatal("TTL keys are not independent")
	}
}
