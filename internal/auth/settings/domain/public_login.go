package domain

import "errors"

var (
	ErrMethodDisabled       = errors.New("login method disabled")
	ErrRegistrationDisabled = errors.New("public registration disabled")
	ErrPolicyUnavailable    = errors.New("auth policy unavailable")
)

// PrimaryMethod maps only the fixed providers supported by this release.
func PrimaryMethod(method, issuer string) string {
	if issuer == "" && (method == "password" || method == "emailotp") {
		return method
	}
	if method == "oidc" {
		switch issuer {
		case "https://accounts.google.com":
			return "google"
		case "https://oauth.telegram.org":
			return "telegram"
		}
	}
	return ""
}

func (p Policy) RequireMethod(method string, registration bool) error {
	var enabled, registrationEnabled bool
	switch method {
	case "password":
		enabled, registrationEnabled = p.Methods.Password, p.Registration.Enabled
	case "emailotp":
		enabled = p.Methods.EmailOTP
	case "google":
		enabled, registrationEnabled = p.Methods.Google, p.Registration.Enabled && p.Registration.Google
	case "telegram":
		enabled, registrationEnabled = p.Methods.Telegram, p.Registration.Enabled && p.Registration.Telegram
	}
	if !enabled {
		return ErrMethodDisabled
	}
	if registration && !registrationEnabled {
		return ErrRegistrationDisabled
	}
	return nil
}
