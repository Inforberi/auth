package service

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

type Config struct {
	Enabled              bool          `env:"MFA_ENABLED" env-default:"false"`
	RecoveryEnabled      bool          `env:"MFA_RECOVERY_ENABLED" env-default:"false"`
	Issuer               string        `env:"MFA_ISSUER" env-default:"Auth"`
	ChallengeTTL         time.Duration `env:"MFA_LOGIN_CHALLENGE_TTL" env-default:"5m"`
	UserLimitPerMinute   int           `env:"MFA_USER_OPERATIONS_PER_MINUTE" env-default:"5"`
	IPLimitPerMinute     int           `env:"MFA_IP_OPERATIONS_PER_MINUTE" env-default:"10"`
	GlobalLimitPerMinute int           `env:"MFA_PROJECT_OPERATIONS_PER_MINUTE" env-default:"500"`
}

func (c Config) Validate() error {
	if c.RecoveryEnabled && !c.Enabled {
		return fmt.Errorf("MFA_RECOVERY_ENABLED requires MFA_ENABLED")
	}
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Issuer) == "" || len(c.Issuer) > 100 || !utf8.ValidString(c.Issuer) || strings.ContainsAny(c.Issuer, "\x00\r\n") {
		return fmt.Errorf("MFA_ISSUER must be a readable name of at most 100 bytes")
	}
	if c.ChallengeTTL < time.Minute || c.ChallengeTTL > 5*time.Minute || c.UserLimitPerMinute < 2 || c.IPLimitPerMinute < 2 || c.GlobalLimitPerMinute < 2 {
		return fmt.Errorf("MFA challenge TTL must be 1m..5m and operation budgets at least 2 to allow start and completion")
	}
	return nil
}
