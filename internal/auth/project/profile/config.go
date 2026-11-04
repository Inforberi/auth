package profile

import (
	"time"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

type ProjectProfileConfig struct {
	BrowserEnabled           bool
	UserDirectoryEnabled     bool
	UserLifecycleEnabled     bool
	AuthSettingsEnabled      bool
	ProviderSettingsEnabled  bool
	RetentionSettingsEnabled bool
	MFASettingsEnabled       bool
	SMTPSettings             *projectsettings.ProjectSMTPSettingsConfig
	Access                   *accesssettings.Catalog
	Password                 *projectmethods.ProjectPasswordConfig
	EmailOTP                 *projectmethods.ProjectEmailOTPConfig
	EmailMFA                 *projectmfa.ProjectEmailMFAConfig
	TelegramMFA              bool
	Google, Telegram         *projectmethods.ProjectOIDCConfig
	Verification             *accountservice.Config
	Recovery                 *passwordrecovery.Config
	EmailManagement          *projectaccount.ProjectEmailConfig
	Tokens                   *projectnative.ProjectTokenConfig
	Timeout                  time.Duration
}

type ProjectProfileDependencies struct {
	projectnative.ProjectTokenDependencies
	OIDCClients *projectmethods.ProjectOIDCClients
	BotAPI      projectmfa.ProjectTelegramClient
	Delivery    ProjectDeliveryState
	SMTPTests   *settingssmtp.SMTPTestGate
}

type ProjectDeliveryState interface {
	ActiveFor(projectbinding.ProjectSMTPDependencies) bool
	AllowedTargets() []string
}
