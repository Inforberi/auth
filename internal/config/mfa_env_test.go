package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	mfa "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestMFAConfiguration(t *testing.T) {
	t.Setenv("MFA_ENABLED", "true")
	t.Setenv("MFA_ISSUER", "Example Auth")
	t.Setenv("MFA_LOGIN_CHALLENGE_TTL", "3m")
	t.Setenv("MFA_USER_OPERATIONS_PER_MINUTE", "12")
	t.Setenv("MFA_IP_OPERATIONS_PER_MINUTE", "30")
	t.Setenv("MFA_PROJECT_OPERATIONS_PER_MINUTE", "5000")
	var c mfa.Config
	if err := cleanenv.ReadEnv(&c); err != nil || c.Validate() != nil {
		t.Fatal(err, c)
	}
	if c.Issuer != "Example Auth" || c.ChallengeTTL != 3*time.Minute || c.UserLimitPerMinute != 12 || c.IPLimitPerMinute != 30 || c.GlobalLimitPerMinute != 5000 {
		t.Fatal("MFA env ignored")
	}
	for _, mutate := range []func(*mfa.Config){
		func(c *mfa.Config) { c.Issuer = "" }, func(c *mfa.Config) { c.Issuer = "invalid\nname" },
		func(c *mfa.Config) { c.ChallengeTTL = time.Second }, func(c *mfa.Config) { c.ChallengeTTL = 6 * time.Minute },
		func(c *mfa.Config) { c.UserLimitPerMinute = 0 }, func(c *mfa.Config) { c.IPLimitPerMinute = 0 }, func(c *mfa.Config) { c.GlobalLimitPerMinute = 0 },
		func(c *mfa.Config) { c.UserLimitPerMinute = 1 }, func(c *mfa.Config) { c.IPLimitPerMinute = 1 }, func(c *mfa.Config) { c.GlobalLimitPerMinute = 1 },
	} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid MFA config accepted", bad)
		}
	}
	if (mfa.Config{}).Validate() != nil {
		t.Fatal("disabled MFA requires configuration")
	}
}
