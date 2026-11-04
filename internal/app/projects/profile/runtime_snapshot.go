package profile

import runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"

func (p *profileAssembly) runtimeSnapshot() *runtimeprofile.ProjectProfile {
	return runtimeprofile.New(runtimeprofile.Definition{
		Key:                 p.key,
		Origin:              p.origin,
		Policy:              p.policy,
		Dependencies:        p.deps,
		States:              p.states,
		ObservedAt:          p.observedAt,
		Password:            p.password,
		EmailOTP:            p.emailOTP,
		Google:              p.google,
		Telegram:            p.telegram,
		Verification:        p.verification,
		Recovery:            p.recovery,
		Binding:             p.binding,
		Change:              p.change,
		Provisioning:        p.provisioning,
		Activation:          p.activation,
		BindingConfirmation: p.bindingConfirmation,
		ChangeProtection:    p.changeProtection,
		Tokens:              p.tokens,
		MFA:                 p.mfa,
		MFAManagement:       p.mfaManagement,
		MFARecovery:         p.mfaRecovery,
		EmailMFA:            p.emailMFA,
		TelegramMFA:         p.telegramMFA,
		UserDirectory:       p.userDirectory,
		UserLifecycle:       p.userLifecycle,
		Access:              p.access,
		AuthSettings:        p.authSettings,
		SMTPSettings:        p.smtpSettings,
		ProviderSettings:    p.providerSettings,
		RetentionSettings:   p.retentionSettings,
		MFASettings:         p.mfaSettings,
	})
}
