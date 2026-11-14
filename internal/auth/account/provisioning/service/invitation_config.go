package service

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

type InvitationConfig struct {
	Enabled                       bool                                                        `env:"INVITATIONS_ENABLED" env-default:"false"`
	URL                           string                                                      `env:"INVITATION_URL"`
	TTL                           time.Duration                                               `env:"INVITATION_TTL" env-default:"24h"`
	TTLSource                     func(context.Context) (time.Duration, error)                `env:"-"`
	URLSource                     func(context.Context) (string, error)                       `env:"-"`
	ActivationGlobalLimit         int                                                         `env:"ACTIVATION_GLOBAL_LIMIT" env-default:"100"`
	ReissueCooldown               time.Duration                                               `env:"INVITATION_REISSUE_COOLDOWN" env-default:"1m"`
	ReissuePolicySource           func(context.Context) (time.Duration, time.Duration, error) `env:"-"`
	IssueActorAttemptsPerMinute   int                                                         `env:"INVITATION_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE" env-default:"30"`
	IssueProjectAttemptsPerMinute int                                                         `env:"INVITATION_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE" env-default:"100"`
	BudgetSource                  func(context.Context) (int, int, int, error)                `env:"-"`
}

func (c InvitationConfig) Validate(production bool) error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || len(c.URL) > 2048 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid INVITATION_URL")
	}
	if production && u.Scheme != "https" {
		return fmt.Errorf("production invitation URL must use HTTPS")
	}
	if c.TTL < time.Minute || c.TTL > 7*24*time.Hour || c.ActivationGlobalLimit < 1 {
		return fmt.Errorf("invalid invitation budgets")
	}
	if c.ReissueCooldown < time.Second || c.ReissueCooldown > 24*time.Hour || c.IssueActorAttemptsPerMinute < 1 || c.IssueProjectAttemptsPerMinute < 1 {
		return fmt.Errorf("invalid invitation issuance budgets")
	}
	return nil
}
