package service

import (
	"fmt"
	"time"
)

type EmailBindingConfig struct {
	Enabled                bool          `env:"EMAIL_BINDING_ENABLED" env-default:"false"`
	TTL                    time.Duration `env:"EMAIL_BINDING_TTL" env-default:"5m"`
	RequestsPerMinute      int           `env:"EMAIL_BINDING_REQUESTS_PER_MINUTE" env-default:"100"`
	ConfirmationsPerMinute int           `env:"EMAIL_BINDING_CONFIRMATIONS_PER_MINUTE" env-default:"1000"`
}

func (c EmailBindingConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.TTL < time.Minute || c.TTL > 5*time.Minute || c.RequestsPerMinute < 1 || c.ConfirmationsPerMinute < 1 {
		return fmt.Errorf("invalid EMAIL_BINDING_TTL or per-minute budgets")
	}
	return nil
}
