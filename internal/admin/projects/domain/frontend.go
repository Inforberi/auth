package domain

import (
	"strings"

	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func FrontendDefaults(origin string) settings.FrontendPolicy {
	return settings.FrontendPolicy{
		Origins: origin, VerificationURL: origin + "/verify-email", ResetURL: origin + "/reset-password",
		InvitationURL: origin + "/activate", EmailChangeURL: origin + "/change-email",
		EmailChangeReportURL: origin + "/protect-account", EmailChangeRecoveryURL: origin + "/recover-account",
	}
}

func ValidateProjectFrontend(policy settings.FrontendPolicy, origin string, allowed []string) error {
	if err := policy.Validate(append([]string{origin}, allowed...)); err != nil {
		return err
	}
	for _, address := range []string{policy.VerificationURL, policy.ResetURL, policy.InvitationURL,
		policy.EmailChangeURL, policy.EmailChangeReportURL, policy.EmailChangeRecoveryURL} {
		if !strings.HasPrefix(address, origin+"/") || strings.HasPrefix(address, origin+"//") {
			return settings.ErrInvalidFrontend
		}
	}
	return nil
}
