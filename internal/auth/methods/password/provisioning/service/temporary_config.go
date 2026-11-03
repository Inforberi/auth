package service

import (
	"fmt"
	"time"
)

type TemporaryPasswordConfig struct {
	Enabled                       bool          `env:"TEMPORARY_PASSWORD_ENABLED" env-default:"false"`
	TTL                           time.Duration `env:"TEMPORARY_PASSWORD_TTL" env-default:"24h"`
	SetupTTL                      time.Duration `env:"TEMPORARY_PASSWORD_SETUP_TTL" env-default:"10m"`
	ReissueCooldown               time.Duration `env:"TEMPORARY_PASSWORD_REISSUE_COOLDOWN" env-default:"1m"`
	IssueActorAttemptsPerMinute   int           `env:"TEMPORARY_PASSWORD_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE" env-default:"30"`
	IssueProjectAttemptsPerMinute int           `env:"TEMPORARY_PASSWORD_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"100"`
	SetupProjectAttemptsPerMinute int           `env:"TEMPORARY_PASSWORD_SETUP_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"100"`
}

func (c TemporaryPasswordConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.TTL < time.Minute || c.TTL > 7*24*time.Hour || c.SetupTTL < time.Minute || c.SetupTTL > 30*time.Minute || c.SetupTTL > c.TTL {
		return fmt.Errorf("invalid temporary password lifetimes")
	}
	if c.ReissueCooldown < time.Second || c.ReissueCooldown > 24*time.Hour || c.IssueActorAttemptsPerMinute < 1 || c.IssueProjectAttemptsPerMinute < 1 || c.SetupProjectAttemptsPerMinute < 1 {
		return fmt.Errorf("invalid temporary password budgets")
	}
	return nil
}
