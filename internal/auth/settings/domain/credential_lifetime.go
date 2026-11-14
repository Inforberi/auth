package domain

import "errors"

var ErrInvalidCredentialLifetime = errors.New("invalid credential lifetime policy")

type CredentialLifetimePolicy struct {
	MFAChallengeSeconds             int64 `json:"mfaChallengeSeconds"`
	FreshAuthSeconds                int64 `json:"freshAuthSeconds"`
	EmailBindingSeconds             int64 `json:"emailBindingSeconds"`
	InvitationSeconds               int64 `json:"invitationSeconds"`
	InvitationCooldownSeconds       int64 `json:"invitationCooldownSeconds"`
	TemporaryReissueCooldownSeconds int64 `json:"temporaryReissueCooldownSeconds"`
	TemporaryPasswordSeconds        int64 `json:"temporaryPasswordSeconds"`
	TemporarySetupSeconds           int64 `json:"temporarySetupSeconds"`
	EmailChangeSeconds              int64 `json:"emailChangeSeconds"`
	EmailChangeRecoverySeconds      int64 `json:"emailChangeRecoverySeconds"`
	EmailChangeProtectionSeconds    int64 `json:"emailChangeProtectionSeconds"`
}

func (p CredentialLifetimePolicy) Validate() error {
	switch {
	case p.FreshAuthSeconds < 60 || p.FreshAuthSeconds > 900,
		p.MFAChallengeSeconds < 60 || p.MFAChallengeSeconds > 300,
		p.EmailBindingSeconds < 60 || p.EmailBindingSeconds > 300,
		p.InvitationCooldownSeconds < 1 || p.InvitationCooldownSeconds > 86400,
		p.TemporaryReissueCooldownSeconds < 1 || p.TemporaryReissueCooldownSeconds > 86400,
		p.InvitationSeconds < 60 || p.InvitationSeconds > 604800,
		p.TemporaryPasswordSeconds < 60 || p.TemporaryPasswordSeconds > 604800,
		p.TemporarySetupSeconds < 60 || p.TemporarySetupSeconds > 1800 || p.TemporarySetupSeconds > p.TemporaryPasswordSeconds,
		p.EmailChangeSeconds < 60 || p.EmailChangeSeconds > 3600,
		p.EmailChangeRecoverySeconds < 60 || p.EmailChangeRecoverySeconds > 3600,
		p.EmailChangeProtectionSeconds > 172800 || p.EmailChangeProtectionSeconds < 2*p.EmailChangeSeconds:
		return ErrInvalidCredentialLifetime
	}
	return nil
}
