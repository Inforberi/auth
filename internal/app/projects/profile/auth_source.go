package profile

import (
	"context"
	"slices"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

type compiledProjectDeployment struct {
	methods projectMethodDeployment
	tokens  *projectnative.ProjectTokenConfig
	access  *accesssettings.Catalog
}

type ProjectAuthDeployment struct {
	legacy           projectprofile.ProjectProfileSource
	smtpTargets      []string
	realm            projectdomain.ID
	entries          map[projectdomain.ID]compiledProjectDeployment
	google, telegram projectmethods.ProjectOIDCConfig
	otp              otpservice.Config
	emailMFA         projectmfa.ProjectEmailMFAConfig
	oidc, jwt        bool
	botAPI           bool
}

func (d *ProjectAuthDeployment) NeedsBotAPI() bool { return d.botAPI }

func (d *ProjectAuthDeployment) NeedsOIDC() bool { return d.oidc }

func (d *ProjectAuthDeployment) NeedsTokenRedis() bool { return d.jwt }

func LoadProjectAuthDeployment(cfg *config.Config) (*ProjectAuthDeployment, error) {
	if cfg == nil || !projectdomain.ValidID(projectdomain.ID(cfg.Platform.RealmID)) {
		return nil, errProjectAuthManifest
	}
	d := &ProjectAuthDeployment{legacy: projectBrowserDeployment(cfg), smtpTargets: slices.Clone(cfg.Platform.Delivery.Targets()), realm: projectdomain.ID(cfg.Platform.RealmID), otp: cfg.EmailOTP}
	d.otp.CheckPolicy = nil
	if cfg.Platform.HTTP.ManifestFile == "" {
		return d, nil
	}
	manifest, err := loadProjectAuthManifest(cfg.Platform.HTTP.ManifestFile)
	if err != nil {
		return nil, err
	}
	d.entries = make(map[projectdomain.ID]compiledProjectDeployment, len(manifest.Projects))
	d.google = projectmethods.ProjectOIDCConfig{Provider: "google", Enabled: true, IPLimit: cfg.Google.IPLimit, GlobalLimit: cfg.Google.GlobalLimit, MFA: cfg.MFA, Session: cfg.Session, Timeout: cfg.Platform.HTTP.BuildTimeout}
	d.telegram = projectmethods.ProjectOIDCConfig{Provider: "telegram", Enabled: true, IPLimit: cfg.Telegram.IPLimit, GlobalLimit: cfg.Telegram.GlobalLimit, MFA: cfg.MFA, Session: cfg.Session, Timeout: cfg.Platform.HTTP.BuildTimeout}
	d.google.MFA.RecoveryEnabled, d.telegram.MFA.RecoveryEnabled = false, false
	consumerHashes := make(map[string]projectdomain.ID)
	for _, entry := range manifest.Projects {
		if entry.TelegramMFA {
			if err := validateTelegramMFADeployment(cfg); err != nil {
				return nil, errProjectAuthManifest
			}
			d.botAPI = true
		}
		if entry.EmailMFA {
			d.emailMFA, err = compileProjectEmailMFA(cfg)
			if err != nil {
				return nil, err
			}
		}
		compiled := compiledProjectDeployment{methods: entry}
		compiled.access, err = compileProjectAccess(entry.Access)
		if err != nil {
			return nil, err
		}
		if entry.JWT != nil {
			compiled.tokens, err = compileProjectJWT(cfg, entry)
			if err != nil {
				return nil, errProjectAuthManifest
			}
			for _, client := range entry.JWT.Clients {
				for _, hash := range client.SecretHashes {
					if owner, exists := consumerHashes[hash]; exists && owner != entry.ID {
						return nil, errProjectAuthManifest
					}
					consumerHashes[hash] = entry.ID
				}
			}
			d.jwt = true
		}
		compiled.methods.JWT, compiled.methods.Access = nil, nil
		d.entries[entry.ID] = compiled
		d.oidc = d.oidc || entry.Google || entry.Telegram
	}
	return d, nil
}

func (d *ProjectAuthDeployment) Profile(ctx context.Context, key projectruntime.Key, origin string) (projectprofile.ProjectProfileConfig, error) {
	if d == nil || d.legacy == nil {
		return projectprofile.ProjectProfileConfig{}, projectdomain.ErrUnavailable
	}
	if !key.Valid() || key.Binding.RealmID != d.realm {
		return projectprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
	}
	base, err := d.legacy(ctx, key, origin)
	if err != nil || d.entries == nil {
		return base, err
	}
	entry, ok := d.entries[key.Binding.ProjectID]
	if !ok {
		return projectprofile.ProjectProfileConfig{Timeout: base.Timeout}, nil
	}
	profile := d.browserProfile(base, entry.methods)
	if entry.access != nil {
		catalog := *entry.access
		profile.Access = &catalog
	}
	if entry.methods.Google {
		google := d.google
		google.RedirectURI = origin + "/api/v1/auth/google/callback"
		profile.Google = &google
	}
	if entry.methods.Telegram {
		telegram := d.telegram
		telegram.RedirectURI = origin + "/api/v1/auth/telegram/callback"
		profile.Telegram = &telegram
	}
	if entry.tokens != nil {
		tokens := cloneProjectTokenConfig(*entry.tokens)
		tokens.Issuer = origin
		profile.Tokens = &tokens
		if tokens.Native.PasswordEnabled {
			profile.Verification = base.Verification
		}
	}
	d.applyEmailMFA(&profile, entry.methods.EmailMFA)
	if entry.methods.TelegramMFA {
		enableProjectMFARecovery(&profile)
	}
	profile.TelegramMFA = entry.methods.TelegramMFA
	return profile, nil
}

func (d *ProjectAuthDeployment) browserProfile(base projectprofile.ProjectProfileConfig, methods projectMethodDeployment) projectprofile.ProjectProfileConfig {
	profile := projectprofile.ProjectProfileConfig{BrowserEnabled: methods.Browser, UserDirectoryEnabled: methods.UserDirectory, UserLifecycleEnabled: methods.UserLifecycle, AuthSettingsEnabled: methods.AuthSettings, ProviderSettingsEnabled: methods.ProviderSettings, RetentionSettingsEnabled: methods.RetentionSettings, MFASettingsEnabled: methods.MFASettings, Timeout: base.Timeout}
	if methods.SMTPSettings {
		profile.SMTPSettings = &projectsettings.ProjectSMTPSettingsConfig{AllowedTargets: slices.Clone(d.smtpTargets)}
	}
	if methods.Browser {
		password := *base.Password
		password.TemporaryPassword.Enabled = methods.TemporaryPassword
		profile.Password, profile.Verification, profile.Recovery = &password, base.Verification, base.Recovery
		if base.EmailManagement != nil && (methods.EmailBinding || methods.EmailChange || methods.Invitations) {
			email := *base.EmailManagement
			email.Binding.Enabled, email.Change.Enabled = methods.EmailBinding, methods.EmailChange
			email.Invitations.Enabled = methods.Invitations
			profile.EmailManagement = &email
		}
	}
	if methods.Browser && (methods.EmailOTP || methods.Reauthentication) {
		otp := d.otp
		otp.Enabled, otp.ReauthenticationEnabled = methods.EmailOTP, methods.Reauthentication
		profile.EmailOTP = &projectmethods.ProjectEmailOTPConfig{OTP: otp, MFA: base.Password.MFA, Session: base.Password.Session, Timeout: base.Timeout}
	}
	return profile
}

func compileProjectAccess(deployment *projectAccessDeployment) (*accesssettings.Catalog, error) {
	if deployment == nil {
		return nil, nil
	}
	catalog, err := accesssettings.NewCatalog(deployment.Permissions)
	if err != nil {
		return nil, errProjectAuthManifest
	}
	return &catalog, nil
}

func validateTelegramMFADeployment(cfg *config.Config) error {
	if !cfg.MFA.Enabled || cfg.MFA.Validate() != nil || !cfg.Platform.Delivery.Enabled || cfg.Platform.Delivery.ValidateTargets() != nil {
		return errProjectAuthManifest
	}
	return nil
}
