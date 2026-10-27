package auth

import "context"

func (p *ProjectProfile) buildProfileProvisioning(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
	if !cfg.BrowserEnabled {
		return
	}
	if cfg.Password != nil && cfg.Password.TemporaryPassword.Enabled {
		switch {
		case !p.featureReady("temporary_password"):
			p.state("temporary_password_admin", "password_unavailable")
		case p.mfaManagement == nil:
			p.state("temporary_password_admin", "mfa_unavailable")
		default:
			p.state("temporary_password_admin", "")
		}
	}
	if cfg.EmailManagement == nil || !cfg.EmailManagement.Invitations.Enabled {
		return
	}
	management := cfg.EmailManagement
	if management.Origin != p.origin {
		p.state("provisioning", "origin_mismatch")
		p.state("invitation_activation", "origin_mismatch")
		return
	}
	email := ProjectEmailConfig{Origin: p.origin, Invitations: management.Invitations, Verification: management.Verification, Password: management.Password}
	p.activation = p.storedProfileEmail(ctx, "invitation_activation", email, redisReady)
	if p.mfaManagement == nil {
		p.state("provisioning", "mfa_unavailable")
		return
	}
	p.provisioning = p.profileEmail(ctx, "provisioning", email, redisReady)
}
