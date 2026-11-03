package auth

import (
	"errors"
	"net/url"
	"time"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type ProjectEmailConfig struct {
	VerificationEnabled bool
	RecoveryEnabled     bool
	Origin              string
	Verification        accountservice.Config
	Password            passwordrecovery.Config
	Invitations         accountprovisioning.InvitationConfig
	Binding             accountemail.EmailBindingConfig
	Change              accountemail.EmailChangeConfig
	FreshAuthTTL        time.Duration
}

func (c ProjectEmailConfig) validate() error {
	var urls []string
	if c.VerificationEnabled {
		if err := c.Verification.Validate(true); err != nil {
			return err
		}
		urls = append(urls, c.Verification.URL)
	}
	if c.RecoveryEnabled {
		if err := c.Password.Validate(); err != nil {
			return err
		}
		urls = append(urls, c.Password.ResetURL)
	}
	if c.Change.Enabled && c.Password.ResetGlobalLimit < 0 {
		return errors.New("invalid protected recovery budget")
	}
	if err := c.validateAccountFeatures(); err != nil {
		return err
	}
	return validateProjectEmailOrigin(c.Origin, urls...)
}

func (c ProjectEmailConfig) validateAccountFeatures() error {
	if err := c.Invitations.Validate(true); err != nil {
		return err
	}
	if err := c.Binding.Validate(); err != nil {
		return err
	}
	if err := c.Change.Validate(true); err != nil {
		return err
	}
	if c.Invitations.Enabled {
		if err := validateProjectEmailOrigin(c.Origin, c.Invitations.URL); err != nil {
			return err
		}
	}
	if c.Change.Enabled {
		if err := sessionservice.ValidateFreshAuthTTL(c.FreshAuthTTL); err != nil {
			return err
		}
		return validateProjectEmailOrigin(c.Origin, c.Change.ConfirmURL, c.Change.ReportURL, c.Change.RecoveryURL)
	}
	return nil
}

func validateProjectEmailOrigin(originURL string, urls ...string) error {
	origin, err := url.Parse(originURL)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("project email requires a trusted HTTPS origin")
	}
	for _, raw := range urls {
		target, err := url.Parse(raw)
		if err != nil || target.Scheme != origin.Scheme || target.Host != origin.Host {
			return errors.New("project email URL must use its trusted origin")
		}
	}
	return nil
}
