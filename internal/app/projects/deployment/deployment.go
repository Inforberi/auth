package deployment

import (
	"context"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func projectBrowserDeployment(cfg *config.Config) projectprofile.ProjectProfileSource {
	// Capture only operational values; never retain a platform encryption key or provider secret.
	session, mfa, capacity := cfg.Session, cfg.MFA, cfg.Capacity
	mfa.RecoveryEnabled = false
	verification, recovery := cfg.Account, cfg.Password
	binding, change := cfg.EmailBinding, cfg.EmailChange
	invitations, temporary := cfg.Invitation, cfg.TemporaryPassword
	invitations.Enabled, temporary.Enabled = false, false
	verification.EncryptionKey = ""
	withMail, timeout := cfg.Platform.Delivery.Enabled, cfg.Platform.HTTP.BuildTimeout
	return func(_ context.Context, _ projectruntime.Key, origin string) (projectprofile.ProjectProfileConfig, error) {
		profile := projectprofile.ProjectProfileConfig{BrowserEnabled: true, Timeout: timeout, Password: &projectmethods.ProjectPasswordConfig{Session: session, MFA: mfa, TemporaryPassword: temporary, Capacity: capacity, Timeout: timeout}}
		projectChange := change
		projectChange.ConfirmURL, projectChange.ReportURL, projectChange.RecoveryURL = origin+"/change-email", origin+"/protect-account", origin+"/recover-account"
		projectRecovery := recovery
		projectRecovery.ResetURL = origin + "/reset-password"
		projectInvitations := invitations
		projectInvitations.URL = origin + "/activate"
		profile.EmailManagement = &projectaccount.ProjectEmailConfig{Invitations: projectInvitations, Origin: origin, Binding: binding, Change: projectChange, Verification: verification, Password: projectRecovery, FreshAuthTTL: session.FreshAuthTTL}
		if withMail {
			verify, reset := verification, recovery
			verify.URL, reset.ResetURL = origin+"/verify-email", origin+"/reset-password"
			profile.Verification, profile.Recovery = &verify, &reset
		}
		return profile, nil
	}
}
