package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type Config struct {
	Enabled             bool   `env:"TELEGRAM_LOGIN_ENABLED" env-default:"false"`
	RegistrationEnabled bool   `env:"TELEGRAM_REGISTRATION_ENABLED" env-default:"false"`
	ClientID            string `env:"TELEGRAM_OIDC_CLIENT_ID"`
	ClientSecret        string `env:"TELEGRAM_OIDC_CLIENT_SECRET"`
	RedirectURI         string `env:"TELEGRAM_OIDC_REDIRECT_URI"`
	IPLimit             int    `env:"TELEGRAM_LOGIN_IP_LIMIT" env-default:"30"`
	GlobalLimit         int    `env:"TELEGRAM_LOGIN_GLOBAL_LIMIT" env-default:"1000"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !settingsdomain.ValidProviderClientID("telegram", c.ClientID) || !settingsdomain.ValidProviderSecret(c.ClientSecret) || strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("telegram login requires valid client ID and secret from BotFather")
	}
	return c.ValidateOperational()
}

func (c Config) ValidateOperational() error {
	u, err := url.Parse(c.RedirectURI)
	if err != nil || len(c.RedirectURI) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v1/auth/telegram/callback" {
		return fmt.Errorf("TELEGRAM_OIDC_REDIRECT_URI must be the HTTPS Telegram callback URL")
	}
	if c.IPLimit < 1 || c.GlobalLimit < 1 {
		return fmt.Errorf("telegram login limits must be positive per-minute budgets")
	}
	return nil
}

func (c Config) FlowConfig() service.Config {
	return service.Config{Enabled: c.Enabled, RegistrationEnabled: c.RegistrationEnabled, IPLimit: c.IPLimit, GlobalLimit: c.GlobalLimit, Issuer: domain.Issuer}
}
