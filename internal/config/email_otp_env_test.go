package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	otp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
)

func TestEmailOTPConfiguration(t *testing.T) {
	t.Setenv("EMAIL_OTP_ENABLED", "true")
	t.Setenv("EMAIL_OTP_TTL", "6m")
	t.Setenv("EMAIL_OTP_RESEND_INTERVAL", "2m")
	t.Setenv("EMAIL_OTP_REQUEST_PROJECT_ATTEMPTS_PER_MINUTE", "300")
	t.Setenv("EMAIL_OTP_CONFIRM_PROJECT_ATTEMPTS_PER_MINUTE", "400")
	var cfg otp.Config
	if err := cleanenv.ReadEnv(&cfg); err != nil || cfg.Validate() != nil {
		t.Fatal(err, cfg)
	}
	if cfg.TTL != 6*time.Minute || cfg.ResendInterval != 2*time.Minute || cfg.RequestGlobalLimit != 300 || cfg.ConfirmGlobalLimit != 400 {
		t.Fatal("env ignored")
	}
	for _, mutate := range []func(*otp.Config){
		func(c *otp.Config) { c.TTL = 30 * time.Second },
		func(c *otp.Config) { c.TTL = 11 * time.Minute },
		func(c *otp.Config) { c.ResendInterval = c.TTL },
		func(c *otp.Config) { c.ResendInterval = time.Second },
		func(c *otp.Config) { c.RequestGlobalLimit = 0 },
		func(c *otp.Config) { c.ConfirmGlobalLimit = 0 },
	} {
		bad := cfg
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if (otp.Config{}).Validate() != nil {
		t.Fatal("disabled profile requires settings")
	}
}
