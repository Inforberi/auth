package methods

import (
	"errors"
	"time"

	googleservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
	telegramservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type ProjectOIDCConfig struct {
	Provider             string
	Enabled              bool
	RedirectURI          string
	IPLimit, GlobalLimit int
	MFA                  mfaservice.Config
	Session              sessionservice.Config
	Timeout              time.Duration
}

func (c ProjectOIDCConfig) validate(deps ProjectOIDCDependencies) error {
	if !settingsdomain.ValidProvider(c.Provider) {
		return settingsdomain.ErrInvalidProvider
	}
	if !c.Enabled {
		return nil
	}
	if deps.Registry == nil || deps.Reader == nil || deps.Redis == nil || deps.Clients.client(c.Provider) == nil || c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("invalid project OIDC dependencies/timeout")
	}
	var err error
	switch c.Provider {
	case "google":
		err = (googleservice.Config{RedirectURI: c.RedirectURI, IPLimit: c.IPLimit, GlobalLimit: c.GlobalLimit}).ValidateOperational()
	case "telegram":
		err = (telegramservice.Config{RedirectURI: c.RedirectURI, IPLimit: c.IPLimit, GlobalLimit: c.GlobalLimit}).ValidateOperational()
	}
	if err != nil {
		return err
	}
	if err := c.Session.Validate(); err != nil {
		return err
	}
	return projectmfa.ValidateProjectMFA(c.MFA)
}
