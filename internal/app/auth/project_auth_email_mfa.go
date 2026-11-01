package auth

import (
	"fmt"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func compileProjectEmailMFA(cfg *config.Config) (ProjectEmailMFAConfig, error) {
	if !cfg.MFA.Enabled || !cfg.Platform.Delivery.Enabled || cfg.Platform.Delivery.ValidateTargets() != nil {
		return ProjectEmailMFAConfig{}, fmt.Errorf("%w: emailMFA requires MFA_ENABLED and project delivery with allowed SMTP targets", errProjectAuthManifest)
	}
	if err := cfg.MFA.Validate(); err != nil {
		return ProjectEmailMFAConfig{}, fmt.Errorf("%w: emailMFA requires valid MFA configuration", errProjectAuthManifest)
	}
	c := cfg.Platform.HTTP.EmailMFA
	result := ProjectEmailMFAConfig{
		Preparation: otpservice.EmailPreparationConfig{TTL: c.PreparationTTL, ResendInterval: c.PreparationResendInterval, RequestsPerMinute: c.PreparationRequestsPerProjectMinute, ConfirmationsPerMinute: c.PreparationConfirmsPerProjectMinute},
		Factors:     mfaservice.EmailFactorConfig{UserMutationsPerMinute: c.UserChangesPerMinute, ProjectMutationsPerMinute: c.ProjectChangesPerMinute},
	}
	if err := result.Validate(); err != nil {
		return ProjectEmailMFAConfig{}, fmt.Errorf("%w: invalid PLATFORM_PROJECT_EMAIL_MFA preparation or change budgets", errProjectAuthManifest)
	}
	return result, nil
}

func (d *ProjectAuthDeployment) applyEmailMFA(profile *ProjectProfileConfig, enabled bool) {
	if !enabled {
		return
	}
	settings := d.emailMFA
	profile.EmailMFA = &settings
	enableProjectMFARecovery(profile)
}

func enableProjectMFARecovery(profile *ProjectProfileConfig) {
	if profile.Password != nil {
		profile.Password.MFA.RecoveryEnabled = true
	}
	if profile.EmailOTP != nil {
		profile.EmailOTP.MFA.RecoveryEnabled = true
	}
	for _, method := range []*ProjectOIDCConfig{profile.Google, profile.Telegram} {
		if method != nil {
			method.MFA.RecoveryEnabled = true
		}
	}
	if profile.Tokens != nil && profile.Tokens.Tokens.Native != nil {
		profile.Tokens.Native.MFA.RecoveryEnabled = true
	}
}
