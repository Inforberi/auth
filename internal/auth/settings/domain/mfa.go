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
