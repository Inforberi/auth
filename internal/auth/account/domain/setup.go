package domain

import (
	"errors"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

var (
	ErrSetupClosed           = errors.New("initial setup closed")
	ErrSetupUnauthorized     = errors.New("setup operator proof required")
	ErrSetupInvalid          = errors.New("invalid setup confirmation")
	ErrSetupConflict         = errors.New("setup conflict")
	ErrSetupPasswordPolicy   = errors.New("setup password policy")
	ErrDependencyUnavailable = errors.New("dependency unavailable")
)

type SetupAccount struct {
	UserID          UserID
	Email           string
	PasswordHash    string
	MFAMode         settingsdomain.MFAMode
	Factor          []byte
	LastStep        int64
	RecoveryDigests []string
}

func (a SetupAccount) MFAPolicy() (settingsdomain.MFAPolicy, error) {
	mode := a.MFAMode
	if mode == "" {
		mode = settingsdomain.MFAAdministrators
	}
	policy := settingsdomain.MFAPolicy{Mode: mode}
	if policy.Validate() != nil ||
		(mode != settingsdomain.MFAOptional && len(a.Factor) == 0) ||
		(mode == settingsdomain.MFAOptional && (len(a.Factor) != 0 || len(a.RecoveryDigests) != 0)) {
		return settingsdomain.MFAPolicy{}, ErrSetupInvalid
	}
	return policy, nil
}
