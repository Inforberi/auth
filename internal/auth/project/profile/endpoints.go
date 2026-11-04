package profile

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	projectaccess "github.com/Inforberi/financial-intelligence/internal/access/project"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type Endpoints struct {
	Password                *projectmethods.ProjectPassword
	EmailOTP                *projectmethods.ProjectEmailOTP
	Google                  *projectmethods.ProjectOIDC
	Telegram                *projectmethods.ProjectOIDC
	Verification            *projectaccount.ProjectEmail
	Recovery                *projectaccount.ProjectEmail
	Binding                 *projectaccount.ProjectEmail
	Change                  *projectaccount.ProjectEmail
	Provisioning            *projectaccount.ProjectEmail
	Activation              *projectaccount.ProjectEmail
	BindingConfirmation     *projectaccount.ProjectEmail
	ChangeProtection        *projectaccount.ProjectEmail
	Tokens                  *projectnative.ProjectTokens
	MFA                     *projectmfa.ProjectMFA
	MFAManagement           *projectmfa.ProjectMFA
	MFARecovery             *projectmfa.ProjectMFARecovery
	EmailMFA                *projectmfa.ProjectEmailMFA
	TelegramMFA             *projectmfa.ProjectTelegramMFA
	UserDirectory           *projectaccount.ProjectUserDirectory
	UserLifecycle           *projectaccount.ProjectUserLifecycle
	Access                  *projectaccess.ProjectAccess
	AuthSettings            *projectsettings.ProjectAuthSettings
	SMTPSettings            *projectsettings.ProjectSMTPSettings
	ProviderSettings        *projectsettings.ProjectProviderSettings
	RetentionSettings       *projectsettings.ProjectRetentionSettings
	MFASettings             *projectsettings.ProjectMFASettings
	Key                     projectruntime.Key
	Origin                  string
	EmailVerificationPolicy settingsdomain.EmailVerification
	Available               func(string) bool
	DeliveryReady           func() bool
	RoutePlan               func() []ProjectRoute
	CheckPolicyCurrent      func(context.Context) error
	Sessions                func(*sessionservice.Config) (*SessionRuntime, error)
	EmailMFASettings        interface {
		Read(context.Context, accessservice.Principal) (settingsdomain.EmailMFASnapshot, error)
		Update(context.Context, settingsservice.EmailMFAUpdate) (settingsdomain.EmailMFASnapshot, error)
	}
}

func (p *ProjectProfile) Endpoints() (Endpoints, error) {
	if p.observedAt.IsZero() || !p.key.Valid() {
		return Endpoints{}, errors.New("unbuilt project HTTP profile")
	}
	e := Endpoints{
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
		Key:                 p.key, Origin: p.origin, EmailVerificationPolicy: p.policy.Policy.PasswordEmailVerification,
		Available: p.featureReady, DeliveryReady: p.deliveryReady, RoutePlan: p.RoutePlan, CheckPolicyCurrent: p.checkPolicyCurrent,
		Sessions: func(fallback *sessionservice.Config) (*SessionRuntime, error) {
			cfg, err := p.httpSessionConfig(fallback)
			if err != nil {
				return nil, err
			}
			return &SessionRuntime{profile: p, cfg: cfg}, nil
		},
	}
	if p.mfaSettings != nil {
		e.EmailMFASettings = projectsettings.NewProjectEmailMFASettings(p.runtimeBinding(), func() bool { return p.emailMFA != nil && p.deliveryReady() }, func(ctx context.Context, pool *pgxpool.Pool) error { return p.emailMFA.CheckSMTP(ctx, pool) })
	}
	return e, nil
}
