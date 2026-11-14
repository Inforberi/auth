package service

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

type Config struct {
	ResetTokenTTL     time.Duration                                `env:"PASSWORD_RESET_TOKEN_TTL" env-required:"true"`
	TTLSource         func(context.Context) (time.Duration, error) `env:"-"`
	URLSource         func(context.Context) (string, error)        `env:"-"`
	ResetURL          string                                       `env:"PASSWORD_RESET_URL" env-required:"true"`
	ResetGlobalLimit  int                                          `env:"PASSWORD_RESET_GLOBAL_LIMIT" env-default:"100"`
	ResetBudgetSource func(context.Context) (int, error)           `env:"-"`
}

func (c Config) Validate() error {
	if c.ResetGlobalLimit < 1 {
		return fmt.Errorf("PASSWORD_RESET_GLOBAL_LIMIT must be positive")
	}
	if c.ResetTokenTTL < time.Minute || c.ResetTokenTTL > time.Hour {
		return fmt.Errorf("PASSWORD_RESET_TOKEN_TTL must be between 1m and 1h")
	}
	reset, err := url.Parse(c.ResetURL)
	if err != nil || len(c.ResetURL) > 2048 || reset.Hostname() == "" || reset.User != nil || reset.RawQuery != "" || reset.Fragment != "" || (reset.Scheme != "https" && reset.Scheme != "http") {
		return fmt.Errorf("invalid PASSWORD_RESET_URL")
	}
	return nil
}
