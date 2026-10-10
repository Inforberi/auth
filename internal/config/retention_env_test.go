package config

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func TestRetentionEnvironment(t *testing.T) {
	keys := []string{"ACCOUNT_EMAIL_RESERVATION_DAYS", "SESSION_RETENTION_DAYS", "SECURITY_AUDIT_RETENTION_DAYS"}
	for _, key := range keys {
		t.Setenv(key, "unused")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	var cfg struct {
		Retention accountservice.RetentionConfig
	}
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	want := accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100, Interval: time.Minute}
	if cfg.Retention != want {
		t.Fatal("retention defaults", cfg.Retention)
	}
	for _, key := range keys {
		t.Setenv(key, "7")
	}
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Retention != (accountservice.RetentionConfig{EmailReservationDays: 7, SessionDays: 7, SecurityAuditDays: 7, BatchSize: 100, Interval: time.Minute}) {
		t.Fatal("nested retention env not applied", cfg.Retention)
	}
	if err := cfg.Retention.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			for _, value := range []string{"0", "-1", "30d", "1.5", "invalid", "", strconv.FormatInt(int64((1<<63-1)/(24*time.Hour))+1, 10)} {
				t.Setenv(key, value)
				var cfg struct {
					Retention accountservice.RetentionConfig
				}
				if err := cleanenv.ReadEnv(&cfg); err != nil {
					continue
				}
				if err := cfg.Retention.Validate(); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("invalid %s=%q accepted: %v", key, value, err)
				}
			}
		})
	}
}
