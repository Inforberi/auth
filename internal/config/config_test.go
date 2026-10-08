package config

import (
	"testing"
	"time"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/server/http"
)

func validConfig() Config {
	return Config{
		Postgres: postgres.Config{URL: "postgres://app:secret@localhost/app", MaxConns: 10, MinConns: 2, MaxConnLifetime: time.Hour, MaxConnIdleTime: time.Minute},
		Server:   httpserver.Config{Port: "8080"}, Logger: logger.Config{Env: "dev", Level: "info"},
		Redis:      redisclient.Config{Host: "localhost", Port: "6379"},
		MailSender: mailer.Config{SMTPHost: "localhost", SMTPPort: "1025", SMTPFrom: "auth@example.com", SMTPDomain: "example.com"},
		Session:    sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute},
		Password:   passwordservice.Config{ResetTokenTTL: time.Hour, ResetURL: "https://example.com/reset"},
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"port":       func(c *Config) { c.Server.Port = "0" },
		"pool":       func(c *Config) { c.Postgres.MinConns = 11 },
		"absolute":   func(c *Config) { c.Session.AbsoluteSessionTTL = time.Minute },
		"threshold":  func(c *Config) { c.Session.SessionRefreshThreshold = c.Session.SessionTTL },
		"secretURL":  func(c *Config) { c.Password.ResetURL = "https://user:password@example.com/reset" },
		"swagger":    func(c *Config) { c.Swagger.Enabled = true },
		"production": func(c *Config) { c.Logger.Env = "prod" },
		"header":     func(c *Config) { c.MailSender.SMTPFrom = "test@example.com\r\nBcc: victim@example.com" },
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

func TestSeparateSessionEnvironment(t *testing.T) {
	t.Setenv("SESSION_TTL", "2h")
	t.Setenv("ABSOLUTE_SESSION_TTL", "5h")
	// Test the exact configuration tags used by startup, without real secrets.
	var cfg sessionservice.Config
	if err := readSession(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 2*time.Hour || cfg.AbsoluteSessionTTL != 5*time.Hour {
		t.Fatal("TTL keys are not independent")
	}
}
