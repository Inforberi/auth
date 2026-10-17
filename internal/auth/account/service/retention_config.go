package service

import (
	"fmt"
	"time"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

const RetentionBatchTimeout = 5 * time.Second

type RetentionConfig struct {
	EmailReservationDays int           `env:"ACCOUNT_EMAIL_RESERVATION_DAYS" env-default:"30"`
	SessionDays          int           `env:"SESSION_RETENTION_DAYS" env-default:"30"`
	SecurityAuditDays    int           `env:"SECURITY_AUDIT_RETENTION_DAYS" env-default:"180"`
	BatchSize            int           `env:"RETENTION_BATCH_SIZE" env-default:"100"`
	Interval             time.Duration `env:"RETENTION_INTERVAL" env-default:"1m"`
}

func (c RetentionConfig) Validate() error {
	if c.BatchSize < 1 || c.BatchSize > 1000 || c.Interval < time.Second || c.Interval > time.Hour {
		return fmt.Errorf("retention batch must be 1..1000 and interval 1s..1h")
	}
	const maxDays = settingsdomain.MaxRetentionDays
	for _, setting := range []struct {
		name string
		days int
	}{
		{"ACCOUNT_EMAIL_RESERVATION_DAYS", c.EmailReservationDays},
		{"SESSION_RETENTION_DAYS", c.SessionDays},
		{"SECURITY_AUDIT_RETENTION_DAYS", c.SecurityAuditDays},
	} {
		if setting.days < 1 || setting.days > maxDays {
			return fmt.Errorf("%s must be between 1 and %d days", setting.name, maxDays)
		}
	}
	return nil
}
