package profile

import settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

// NeedsVerification describes the password methods selected by policy and deployment.
// It does not probe delivery or construct the verification component.
func (cfg ProjectProfileConfig) NeedsVerification(policy settingsdomain.Policy) bool {
	browserPassword := cfg.BrowserEnabled && policy.Methods.Password
	nativePassword := cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil && cfg.Tokens.Native.PasswordEnabled && policy.TokenIssuance.Native && policy.Methods.Password
	return (browserPassword || nativePassword) && policy.PasswordEmailVerification != settingsdomain.VerificationDisabled
}

// NativeReadiness contains observed prerequisites, without resource handles.
type NativeReadiness struct {
	Redis, Delivery, Verification bool
}

type NativeSelection struct {
	Password, Email             bool
	PasswordReason, EmailReason string
}

// SelectNative preserves selection separately from availability so readiness can
// report a selected method's failure without enabling it in the token runtime.
func (cfg ProjectProfileConfig) SelectNative(policy settingsdomain.Policy, ready NativeReadiness) NativeSelection {
	if cfg.Tokens == nil {
		return NativeSelection{}
	}
	tokens := cfg.Tokens
	selected := NativeSelection{Password: policy.TokenIssuance.Native && policy.Methods.Password && tokens.Native.PasswordEnabled, Email: policy.TokenIssuance.Native && policy.Methods.EmailOTP && tokens.Native.EmailOTP.Enabled}
	if selected.Password {
		switch {
		case !ready.Redis:
			selected.PasswordReason = "redis_unavailable"
		case cfg.NeedsVerification(policy) && !ready.Verification:
			selected.PasswordReason = "verification_unavailable"
		}
	}
	if selected.Email {
		switch {
		case !ready.Redis:
			selected.EmailReason = "redis_unavailable"
		case !ready.Delivery:
			selected.EmailReason = "delivery_not_running"
		}
	}
	return selected
}

// EmailMFARecoveryConfigured is the deployment prerequisite for email MFA.
// Actual recovery/management component availability is checked by assembly.
func (cfg ProjectProfileConfig) EmailMFARecoveryConfigured() bool {
	return cfg.BrowserEnabled && cfg.Password != nil && cfg.Password.MFA.Enabled && cfg.Password.MFA.RecoveryEnabled
}

// AssessmentPolicy selects potential methods while retaining unrelated policy
// fields. The caller must never publish this policy as the stored policy.
func (cfg ProjectProfileConfig) AssessmentPolicy(policy settingsdomain.Policy) settingsdomain.Policy {
	native := cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil
	password, email := false, false
	if native {
		password, email = cfg.Tokens.Native.PasswordEnabled, cfg.Tokens.Native.EmailOTP.Enabled
	}
	policy.Methods = settingsdomain.PublicMethods{
		Password: cfg.BrowserEnabled && cfg.Password != nil || password,
		EmailOTP: cfg.BrowserEnabled && cfg.EmailOTP != nil && cfg.EmailOTP.OTP.Enabled || email,
		Google:   cfg.BrowserEnabled && cfg.Google != nil && cfg.Google.Enabled,
		Telegram: cfg.BrowserEnabled && cfg.Telegram != nil && cfg.Telegram.Enabled,
	}
	policy.PasswordEmailVerification = settingsdomain.VerificationDisabled
	policy.TokenIssuance = settingsdomain.TokenIssuance{SessionExchange: cfg.Tokens != nil && cfg.Tokens.Enabled, Native: native}
	return policy
}
