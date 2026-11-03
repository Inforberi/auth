package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestMFAConfiguration(t *testing.T) {
	t.Setenv("MFA_ENABLED", "true")
	t.Setenv("MFA_ISSUER", "Example Auth")
	t.Setenv("MFA_LOGIN_CHALLENGE_TTL", "3m")
	t.Setenv("MFA_USER_OPERATIONS_PER_MINUTE", "12")
	t.Setenv("MFA_IP_OPERATIONS_PER_MINUTE", "30")
	t.Setenv("MFA_PROJECT_OPERATIONS_PER_MINUTE", "5000")
	var c mfaservice.Config
	if err := cleanenv.ReadEnv(&c); err != nil || c.Validate() != nil {
		t.Fatal(err, c)
	}
	if c.Issuer != "Example Auth" || c.ChallengeTTL != 3*time.Minute || c.UserLimitPerMinute != 12 || c.IPLimitPerMinute != 30 || c.GlobalLimitPerMinute != 5000 {
		t.Fatal("MFA env ignored")
	}
	for _, mutate := range []func(*mfaservice.Config){
		func(c *mfaservice.Config) { c.Issuer = "" }, func(c *mfaservice.Config) { c.Issuer = "invalid\nname" },
		func(c *mfaservice.Config) { c.ChallengeTTL = time.Second }, func(c *mfaservice.Config) { c.ChallengeTTL = 6 * time.Minute },
		func(c *mfaservice.Config) { c.UserLimitPerMinute = 0 }, func(c *mfaservice.Config) { c.IPLimitPerMinute = 0 }, func(c *mfaservice.Config) { c.GlobalLimitPerMinute = 0 },
		func(c *mfaservice.Config) { c.UserLimitPerMinute = 1 }, func(c *mfaservice.Config) { c.IPLimitPerMinute = 1 }, func(c *mfaservice.Config) { c.GlobalLimitPerMinute = 1 },
	} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid MFA config accepted", bad)
		}
	}
	if (mfaservice.Config{}).Validate() != nil {
		t.Fatal("disabled MFA requires configuration")
	}
}

func TestMFARecoveryConfiguration(t *testing.T) {
	t.Setenv("MFA_ENABLED", "true")
	t.Setenv("MFA_RECOVERY_ENABLED", "false")
	var c mfaservice.Config
	if err := cleanenv.ReadEnv(&c); err != nil || c.RecoveryEnabled || c.Validate() != nil {
		t.Fatal("disabled recovery", err)
	}
	t.Setenv("MFA_RECOVERY_ENABLED", "true")
	if err := cleanenv.ReadEnv(&c); err != nil || !c.RecoveryEnabled || c.Validate() != nil {
		t.Fatal("recovery env", err)
	}
	c.Enabled = false
	if c.Validate() == nil {
		t.Fatal("recovery without MFA")
	}
	t.Setenv("MFA_RECOVERY_ENABLED", "not-a-bool")
	if err := cleanenv.ReadEnv(&c); err == nil {
		t.Fatal("malformed recovery bool")
	}
}
