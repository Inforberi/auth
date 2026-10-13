package domain

import "errors"

var (
	ErrInvalidCode      = errors.New("invalid MFA code")
	ErrConflict         = errors.New("MFA state conflict")
	ErrProofRequired    = errors.New("fresh primary authentication required")
	ErrLimited          = errors.New("MFA rate limited")
	ErrUnavailable      = errors.New("MFA temporarily unavailable")
	ErrRequiredByPolicy = errors.New("MFA is required by administrative policy")
)

const RecoveryCodeCount = 10

func ValidCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func ValidRecoveryCode(code string) bool {
	if len(code) != 32 {
		return false
	}
	for _, char := range code {
		digit := char >= '0' && char <= '9'
		letter := char >= 'a' && char <= 'f'
		if !digit && !letter {
			return false
		}
	}
	return true
}
