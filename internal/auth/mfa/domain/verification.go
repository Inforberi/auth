package domain

import "time"

type Method string

const (
	TOTP         Method = "totp"
	RecoveryCode Method = "recovery"
)

// Empty means a historical proof whose mechanism was not recorded.
func (m Method) AuthenticationMethod() string {
	switch m {
	case TOTP:
		return "otp"
	case RecoveryCode:
		return "recovery"
	case "":
		return "mfa"
	default:
		return ""
	}
}

type Verification struct {
	Method     Method
	VerifiedAt time.Time
}
