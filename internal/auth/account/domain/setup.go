package domain

import "errors"

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
	Factor          []byte
	LastStep        int64
	RecoveryDigests []string
}
