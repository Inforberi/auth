package domain

import "errors"

type MFAMode string

const (
	MFAOptional       MFAMode = "optional"
	MFAAdministrators MFAMode = "administrators"
	MFARequired       MFAMode = "required"
)

var ErrInvalidMFAPolicy = errors.New("invalid MFA policy")

type MFAPolicy struct {
	Mode MFAMode `json:"mode"`
}

type MFASnapshot struct {
	Version int64     `json:"version"`
	Policy  MFAPolicy `json:"policy"`
}

func (p MFAPolicy) Validate() error {
	switch p.Mode {
	case MFAOptional, MFAAdministrators, MFARequired:
		return nil
	default:
		return ErrInvalidMFAPolicy
	}
}

func (p MFAPolicy) Strengthens(previous MFAPolicy) bool {
	switch p.Mode {
	case MFARequired:
		return previous.Mode != MFARequired
	case MFAAdministrators:
		return previous.Mode == MFAOptional
	default:
		return false
	}
}

// ValidateChange also guards transaction entrypoints that bypass the service.
func (p MFAPolicy) ValidateChange(expected int64) error {
	if expected < 1 || p.Validate() != nil {
		return ErrInvalidMFAPolicy
	}
	return nil
}

// CheckChange uses the locked snapshot after ValidateChange. An unchanged policy does not
// require runtime readiness, but still requires the expected version.
func (s MFASnapshot) CheckChange(expected int64, next MFAPolicy, ready bool) (bool, error) {
	if s.Version != expected {
		return false, ErrPolicyConflict
	}
	if s.Policy == next {
		return false, nil
	}
	if next.Mode != MFAOptional && !ready {
		return false, ErrMethodNotReady
	}
	return true, nil
}
