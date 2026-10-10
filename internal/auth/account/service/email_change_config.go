package service

import (
	"fmt"
	"net/url"
	"time"
)

type EmailChangeConfig struct {
	Enabled       bool          `env:"EMAIL_CHANGE_ENABLED" env-default:"false"`
	ConfirmURL    string        `env:"EMAIL_CHANGE_URL"`
	ReportURL     string        `env:"EMAIL_CHANGE_REPORT_URL"`
	RecoveryURL   string        `env:"EMAIL_CHANGE_RECOVERY_URL"`
	RecoveryTTL   time.Duration `env:"EMAIL_CHANGE_RECOVERY_TTL" env-default:"30m"`
	TTL           time.Duration `env:"EMAIL_CHANGE_TTL" env-default:"30m"`
	ProtectionTTL time.Duration `env:"EMAIL_CHANGE_PROTECTION_TTL" env-default:"24h"`
}

func (c EmailChangeConfig) Validate(production bool) error {
	if !c.Enabled {
		return nil
	}
	for _, address := range []string{c.ConfirmURL, c.ReportURL, c.RecoveryURL} {
		u, err := url.Parse(address)
		if err != nil || len(address) > 2048 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("invalid email change URL")
		}
		if production && u.Scheme != "https" {
			return fmt.Errorf("production email change URLs must use HTTPS")
		}
	}
	if c.TTL < time.Minute || c.TTL > time.Hour || c.ProtectionTTL < 2*c.TTL || c.ProtectionTTL > 48*time.Hour || c.RecoveryTTL < time.Minute || c.RecoveryTTL > time.Hour {
		return fmt.Errorf("invalid email change durations")
	}
	return nil
}
