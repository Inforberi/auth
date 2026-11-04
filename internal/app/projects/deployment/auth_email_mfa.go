package deployment

import (
	"fmt"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func compileProjectEmailMFA(cfg *config.Config) (projectmfa.ProjectEmailMFAConfig, error) {
	if !cfg.MFA.Enabled || !cfg.Platform.Delivery.Enabled || cfg.Platform.Delivery.ValidateTargets() != nil {
		return projectmfa.ProjectEmailMFAConfig{}, fmt.Errorf("%w: emailMFA requires MFA_ENABLED and project delivery with allowed SMTP targets", errProjectAuthManifest)
	}
	if err := cfg.MFA.Validate(); err != nil {
		return projectmfa.ProjectEmailMFAConfig{}, fmt.Errorf("%w: emailMFA requires valid MFA configuration", errProjectAuthManifest)
	}
	c := cfg.Platform.HTTP.EmailMFA
	result := projectmfa.ProjectEmailMFAConfig{
		Preparation: otpservice.EmailPreparationConfig{TTL: c.PreparationTTL, ResendInterval: c.PreparationResendInterval, RequestsPerMinute: c.PreparationRequestsPerProjectMinute, ConfirmationsPerMinute: c.PreparationConfirmsPerProjectMinute},
		Factors:     mfamanagement.EmailFactorConfig{UserMutationsPerMinute: c.UserChangesPerMinute, ProjectMutationsPerMinute: c.ProjectChangesPerMinute},
	}
	if err := result.Validate(); err != nil {
		return projectmfa.ProjectEmailMFAConfig{}, fmt.Errorf("%w: invalid PLATFORM_PROJECT_EMAIL_MFA preparation or change budgets", errProjectAuthManifest)
	}
	return result, nil
}

func (d *ProjectAuthDeployment) applyEmailMFA(profile *projectprofile.ProjectProfileConfig, enabled bool) {
	if !enabled {
		return
	}
	settings := d.emailMFA
	profile.EmailMFA = &settings
	enableProjectMFARecovery(profile)
}

func enableProjectMFARecovery(profile *projectprofile.ProjectProfileConfig) {
	if profile.Password != nil {
		profile.Password.MFA.RecoveryEnabled = true
	}
	if profile.EmailOTP != nil {
		profile.EmailOTP.MFA.RecoveryEnabled = true
	}
	for _, method := range []*projectmethods.ProjectOIDCConfig{profile.Google, profile.Telegram} {
		if method != nil {
			method.MFA.RecoveryEnabled = true
		}
	}
	if profile.Tokens != nil && profile.Tokens.Tokens.Native != nil {
		profile.Tokens.Native.MFA.RecoveryEnabled = true
	}
}
