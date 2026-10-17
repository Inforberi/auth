package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/google/domain"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type Config struct {
	Enabled             bool   `env:"GOOGLE_LOGIN_ENABLED" env-default:"false"`
	RegistrationEnabled bool   `env:"GOOGLE_REGISTRATION_ENABLED" env-default:"false"`
	ClientID            string `env:"GOOGLE_OIDC_CLIENT_ID"`
	ClientSecret        string `env:"GOOGLE_OIDC_CLIENT_SECRET"`
	RedirectURI         string `env:"GOOGLE_OIDC_REDIRECT_URI"`
	IPLimit             int    `env:"GOOGLE_LOGIN_IP_ATTEMPTS_PER_MINUTE" env-default:"30"`
	GlobalLimit         int    `env:"GOOGLE_LOGIN_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"1000"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !settingsdomain.ValidProviderClientID("google", c.ClientID) || !settingsdomain.ValidProviderSecret(c.ClientSecret) || strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("google login requires web OAuth client ID and secret")
	}
	return c.ValidateOperational()
}

func (c Config) ValidateOperational() error {
	u, err := url.Parse(c.RedirectURI)
	if err != nil || len(c.RedirectURI) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v1/auth/google/callback" {
		return fmt.Errorf("GOOGLE_OIDC_REDIRECT_URI must be the HTTPS Google callback URL")
	}
	if c.IPLimit < 1 || c.GlobalLimit < 1 {
		return fmt.Errorf("google per-minute login budgets must be positive")
	}
	return nil
}

func (c Config) FlowConfig() oidcservice.Config {
	return oidcservice.Config{Issuer: domain.Issuer, Enabled: c.Enabled, RegistrationEnabled: c.RegistrationEnabled, IPLimit: c.IPLimit, GlobalLimit: c.GlobalLimit}
}
