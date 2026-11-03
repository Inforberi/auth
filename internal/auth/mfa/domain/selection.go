package domain

type MethodSelection struct {
	Preferred                      Method
	TOTP, Email, Telegram          bool
	Administrative, ConfiguredWeak bool
}

func (s MethodSelection) Select(primary string, administrative bool) (Method, error) {
	if administrative || s.Administrative || primary != "password" {
		return TOTP, nil
	}
	if s.Preferred != "" {
		if s.Preferred == TOTP && s.TOTP || s.Preferred == EmailCode && s.Email || s.Preferred == TelegramCode && s.Telegram {
			return s.Preferred, nil
		}
		return "", ErrUnavailable
	}
	switch {
	case s.TOTP:
		return TOTP, nil
	case s.Email:
		return EmailCode, nil
	case s.Telegram:
		return TelegramCode, nil
	case s.ConfiguredWeak:
		return "", ErrUnavailable
	default:
		// Required enrollment and explicit assisted recovery own the missing-factor path.
		return TOTP, nil
	}
}
