package domain

import "errors"

var ErrInvalidLinkLifetime = errors.New("invalid link lifetime policy")

type LinkLifetimePolicy struct {
	VerificationSeconds int64 `json:"verificationSeconds"`
	ResetSeconds        int64 `json:"resetSeconds"`
}

func (p LinkLifetimePolicy) Validate(verificationResendSeconds int64) error {
	if p.VerificationSeconds < 60 || p.VerificationSeconds > 3600 ||
		p.VerificationSeconds <= verificationResendSeconds || p.ResetSeconds < 60 || p.ResetSeconds > 3600 {
		return ErrInvalidLinkLifetime
	}
	return nil
}
