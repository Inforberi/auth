package profile

import (
	"context"
	"maps"
	"time"

	projectaccess "github.com/Inforberi/financial-intelligence/internal/access/project"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type Definition struct {
	Key                 projectruntime.Key
	Origin              string
	Policy              settingsdomain.Snapshot
	Dependencies        ProjectProfileDependencies
	States              map[string]ProjectFeatureState
	ObservedAt          time.Time
	Password            *projectmethods.ProjectPassword
	EmailOTP            *projectmethods.ProjectEmailOTP
	Google              *projectmethods.ProjectOIDC
	Telegram            *projectmethods.ProjectOIDC
	Verification        *projectaccount.ProjectEmail
	Recovery            *projectaccount.ProjectEmail
	Binding             *projectaccount.ProjectEmail
	Change              *projectaccount.ProjectEmail
	Provisioning        *projectaccount.ProjectEmail
	Activation          *projectaccount.ProjectEmail
	BindingConfirmation *projectaccount.ProjectEmail
	ChangeProtection    *projectaccount.ProjectEmail
	Tokens              *projectnative.ProjectTokens
	MFA                 *projectmfa.ProjectMFA
	MFAManagement       *projectmfa.ProjectMFA
	MFARecovery         *projectmfa.ProjectMFARecovery
	EmailMFA            *projectmfa.ProjectEmailMFA
	TelegramMFA         *projectmfa.ProjectTelegramMFA
	UserDirectory       *projectaccount.ProjectUserDirectory
	UserLifecycle       *projectaccount.ProjectUserLifecycle
	Access              *projectaccess.ProjectAccess
	AuthSettings        *projectsettings.ProjectAuthSettings
	SMTPSettings        *projectsettings.ProjectSMTPSettings
	ProviderSettings    *projectsettings.ProjectProviderSettings
	RetentionSettings   *projectsettings.ProjectRetentionSettings
	MFASettings         *projectsettings.ProjectMFASettings
}

func New(definition Definition) *ProjectProfile {
	return &ProjectProfile{
		key:                 definition.Key,
		origin:              definition.Origin,
		policy:              definition.Policy,
		deps:                definition.Dependencies,
		states:              maps.Clone(definition.States),
		observedAt:          definition.ObservedAt,
		password:            definition.Password,
		emailOTP:            definition.EmailOTP,
		google:              definition.Google,
		telegram:            definition.Telegram,
		verification:        definition.Verification,
		recovery:            definition.Recovery,
		binding:             definition.Binding,
		change:              definition.Change,
		provisioning:        definition.Provisioning,
		activation:          definition.Activation,
		bindingConfirmation: definition.BindingConfirmation,
		changeProtection:    definition.ChangeProtection,
		tokens:              definition.Tokens,
		mfa:                 definition.MFA,
		mfaManagement:       definition.MFAManagement,
		mfaRecovery:         definition.MFARecovery,
		emailMFA:            definition.EmailMFA,
		telegramMFA:         definition.TelegramMFA,
		userDirectory:       definition.UserDirectory,
		userLifecycle:       definition.UserLifecycle,
		access:              definition.Access,
		authSettings:        definition.AuthSettings,
		smtpSettings:        definition.SMTPSettings,
		providerSettings:    definition.ProviderSettings,
		retentionSettings:   definition.RetentionSettings,
		mfaSettings:         definition.MFASettings,
	}
}

func (p *ProjectProfile) Publish(ctx context.Context, observed settingsdomain.Snapshot) error {
	if err := p.checkSnapshotCurrent(ctx, observed); err != nil {
		return err
	}
	p.observedAt = time.Now().UTC()
	return nil
}

func DeliveryReady(deps ProjectProfileDependencies) bool {
	d := deps.Delivery
	return d != nil && d.ActiveFor(projectbinding.ProjectSMTPDependencies{Registry: deps.Registry, Reader: deps.Reader, Redis: deps.Redis})
}
