package auth

import (
	"context"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type compiledProjectDeployment struct {
	methods projectMethodDeployment
	tokens  *ProjectTokenConfig
}

type ProjectAuthDeployment struct {
	legacy           ProjectProfileSource
	realm            projectdomain.ID
	entries          map[projectdomain.ID]compiledProjectDeployment
	google, telegram ProjectOIDCConfig
	otp              otpservice.Config
	oidc, jwt        bool
}

func LoadProjectAuthDeployment(cfg *config.Config) (*ProjectAuthDeployment, error) {
	if cfg == nil || !projectdomain.ValidID(projectdomain.ID(cfg.Platform.RealmID)) {
		return nil, errProjectAuthManifest
	}
	d := &ProjectAuthDeployment{legacy: projectBrowserDeployment(cfg), realm: projectdomain.ID(cfg.Platform.RealmID), otp: cfg.EmailOTP}
	d.otp.CheckPolicy = nil
	if cfg.Platform.HTTP.ManifestFile == "" {
		return d, nil
	}
	manifest, err := loadProjectAuthManifest(cfg.Platform.HTTP.ManifestFile)
	if err != nil {
		return nil, err
	}
	d.entries = make(map[projectdomain.ID]compiledProjectDeployment, len(manifest.Projects))
	d.google = ProjectOIDCConfig{Provider: "google", Enabled: true, IPLimit: cfg.Google.IPLimit, GlobalLimit: cfg.Google.GlobalLimit, MFA: cfg.MFA, Session: cfg.Session, Timeout: cfg.Platform.HTTP.BuildTimeout}
	d.telegram = ProjectOIDCConfig{Provider: "telegram", Enabled: true, IPLimit: cfg.Telegram.IPLimit, GlobalLimit: cfg.Telegram.GlobalLimit, MFA: cfg.MFA, Session: cfg.Session, Timeout: cfg.Platform.HTTP.BuildTimeout}
	d.google.MFA.RecoveryEnabled, d.telegram.MFA.RecoveryEnabled = false, false
	consumerHashes := make(map[string]projectdomain.ID)
	for _, entry := range manifest.Projects {
		compiled := compiledProjectDeployment{methods: entry}
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
		compiled.methods.JWT = nil
		d.entries[entry.ID] = compiled
		d.oidc = d.oidc || entry.Google || entry.Telegram
	}
	return d, nil
}

func (d *ProjectAuthDeployment) Profile(ctx context.Context, key projectruntime.Key, origin string) (ProjectProfileConfig, error) {
	if d == nil || d.legacy == nil {
		return ProjectProfileConfig{}, projectdomain.ErrUnavailable
	}
	if !key.Valid() || key.Binding.RealmID != d.realm {
		return ProjectProfileConfig{}, projectdomain.ErrConflict
	}
	base, err := d.legacy(ctx, key, origin)
	if err != nil || d.entries == nil {
		return base, err
	}
	entry, ok := d.entries[key.Binding.ProjectID]
	if !ok {
		return ProjectProfileConfig{Timeout: base.Timeout}, nil
	}
	profile := ProjectProfileConfig{BrowserEnabled: entry.methods.Browser, UserDirectoryEnabled: entry.methods.UserDirectory, UserLifecycleEnabled: entry.methods.UserLifecycle, Timeout: base.Timeout}
	if entry.methods.Browser {
		password := *base.Password
		password.TemporaryPassword.Enabled = entry.methods.TemporaryPassword
		profile.Password, profile.Verification, profile.Recovery = &password, base.Verification, base.Recovery
		if base.EmailManagement != nil && (entry.methods.EmailBinding || entry.methods.EmailChange || entry.methods.Invitations) {
			email := *base.EmailManagement
			email.Binding.Enabled, email.Change.Enabled = entry.methods.EmailBinding, entry.methods.EmailChange
			email.Invitations.Enabled = entry.methods.Invitations
			profile.EmailManagement = &email
		}
	}
	if entry.methods.Browser && (entry.methods.EmailOTP || entry.methods.Reauthentication) {
		otp := d.otp
		otp.Enabled, otp.ReauthenticationEnabled = entry.methods.EmailOTP, entry.methods.Reauthentication
		profile.EmailOTP = &ProjectEmailOTPConfig{OTP: otp, MFA: base.Password.MFA, Session: base.Password.Session, Timeout: base.Timeout}
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
	return profile, nil
}
