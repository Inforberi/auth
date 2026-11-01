package domain

import "time"

type Method string

const (
	TOTP         Method = "totp"
	RecoveryCode Method = "recovery"
	EmailCode    Method = "email"
	TelegramCode Method = "telegram"
)

// Empty means a historical proof whose mechanism was not recorded.
func (m Method) AuthenticationMethod() string {
	switch m {
	case TOTP:
		return "otp"
	case RecoveryCode:
		return "recovery"
	case EmailCode:
		return "email_otp"
	case TelegramCode:
		return "telegram_otp"
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
