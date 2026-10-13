package service

import (
	"fmt"
	"time"
)

type Config struct {
	Enabled                 bool          `env:"EMAIL_OTP_ENABLED" env-default:"false"`
	ReauthenticationEnabled bool          `env:"EMAIL_REAUTHENTICATION_ENABLED" env-default:"false"`
	TTL                     time.Duration `env:"EMAIL_OTP_TTL" env-default:"5m"`
	ResendInterval          time.Duration `env:"EMAIL_OTP_RESEND_INTERVAL" env-default:"1m"`
	RequestGlobalLimit      int           `env:"EMAIL_OTP_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"100"`
	ConfirmGlobalLimit      int           `env:"EMAIL_OTP_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"1000"`
}

func (c Config) Validate() error {
	if !c.Enabled && !c.ReauthenticationEnabled {
		return nil
	}
	if c.TTL < time.Minute || c.TTL > 10*time.Minute || c.ResendInterval < time.Minute || c.ResendInterval >= c.TTL {
		return fmt.Errorf("invalid EMAIL_OTP_TTL or EMAIL_OTP_RESEND_INTERVAL")
	}
	if c.RequestGlobalLimit < 1 || c.ConfirmGlobalLimit < 1 {
		return fmt.Errorf("email OTP project per-minute budgets must be positive")
	}
	return nil
}
