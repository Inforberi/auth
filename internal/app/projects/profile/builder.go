package profile

import (
	"time"

	projectaccess "github.com/Inforberi/financial-intelligence/internal/access/project"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type profileAssembly struct {
	key                      projectruntime.Key
	origin                   string
	policy                   settingsdomain.Snapshot
	deps                     runtimeprofile.ProjectProfileDependencies
	states                   map[string]runtimeprofile.ProjectFeatureState
	observedAt               time.Time
	password                 *projectmethods.ProjectPassword
	emailOTP                 *projectmethods.ProjectEmailOTP
	google, telegram         *projectmethods.ProjectOIDC
	verification, recovery   *projectaccount.ProjectEmail
	binding, change          *projectaccount.ProjectEmail
	provisioning, activation *projectaccount.ProjectEmail
	bindingConfirmation      *projectaccount.ProjectEmail
	changeProtection         *projectaccount.ProjectEmail
	tokens                   *projectnative.ProjectTokens
	mfa                      *projectmfa.ProjectMFA
	mfaManagement            *projectmfa.ProjectMFA
	mfaRecovery              *projectmfa.ProjectMFARecovery
	emailMFA                 *projectmfa.ProjectEmailMFA
	telegramMFA              *projectmfa.ProjectTelegramMFA
	userDirectory            *projectaccount.ProjectUserDirectory
	userLifecycle            *projectaccount.ProjectUserLifecycle
	access                   *projectaccess.ProjectAccess
	authSettings             *projectsettings.ProjectAuthSettings
	smtpSettings             *projectsettings.ProjectSMTPSettings
	providerSettings         *projectsettings.ProjectProviderSettings
	retentionSettings        *projectsettings.ProjectRetentionSettings
	mfaSettings              *projectsettings.ProjectMFASettings
}

func (p *profileAssembly) runtimeBinding() projectbinding.Binding {
	return projectbinding.Binding{Key: p.key, Registry: p.deps.Registry, Reader: p.deps.Reader}
}
func (p *profileAssembly) featureReady(name string) bool { return p.states[name].Ready }
func (p *profileAssembly) deliveryReady() bool           { return runtimeprofile.DeliveryReady(p.deps) }

func (p *profileAssembly) feature(feature string, err error) {
	reason := ""
	if err != nil {
		reason = "component_unavailable"
	}
	p.state(feature, reason)
}

func (p *profileAssembly) state(feature, reason string) {
	p.states[feature] = runtimeprofile.ProjectFeatureState{Feature: feature, Ready: reason == "", Reason: reason}
}
