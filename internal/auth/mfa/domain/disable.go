package domain

type DisableState struct {
	Required, Administrative bool
	Email, UsableEmail       bool
	Telegram, UsableTelegram bool
}

func CanDisableTOTP(s DisableState) error {
	if s.Required && !s.UsableEmail && !s.UsableTelegram || (s.Email || s.Telegram) && s.Administrative {
		return ErrRequiredByPolicy
	}
	if s.Email && !s.UsableEmail || s.Telegram && !s.UsableTelegram {
		return ErrRequiredByPolicy
	}
	return nil
}
