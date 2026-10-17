package config

import (
	"fmt"
	"time"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (cfg Config) NativeJWTPolicy() (*tokenservice.NativePolicy, error) {
	if err := cfg.JWT.Validate(); err != nil {
		return nil, err
	}
	if !cfg.JWT.NativeEnabled {
		return nil, nil
	}
	if !cfg.MFA.Enabled {
		return nil, fmt.Errorf("JWT_NATIVE_ENABLED requires MFA_ENABLED (factor requirements remain account policy)")
	}
	policy := tokenservice.NativePolicy{
		IdleTTL: cfg.JWT.RefreshIdleTTL, AbsoluteTTL: cfg.JWT.RefreshAbsoluteTTL, Sessions: cfg.Session,
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("JWT_REFRESH_IDLE_TTL/JWT_REFRESH_ABSOLUTE_TTL must be whole seconds, at least 1m, idle <= absolute and within SESSION_TTL/ABSOLUTE_SESSION_TTL; valid admin session bounds required: %w", err)
	}
	if err := cfg.Retention.Validate(); err != nil {
		return nil, err
	}
	// One worker, including its batch deadline, with half of the calculated budget reserved.
	// This rejects incompatible settings; successful drain still requires operational evidence.
	cycle := cfg.Retention.Interval + accountservice.RetentionBatchTimeout
	if 2*int64(cfg.JWT.ProjectPerMinute)*int64(cycle) > int64(cfg.Retention.BatchSize)*int64(time.Minute) {
		return nil, fmt.Errorf("JWT native cleanup budget mismatch: require 2 * JWT_ISSUANCE_PROJECT_LIMIT_PER_MINUTE * (RETENTION_INTERVAL + %s) <= RETENTION_BATCH_SIZE * 1m; adjust deployment budgets explicitly", accountservice.RetentionBatchTimeout)
	}
	return &policy, nil
}

func (cfg Config) validateNativeJWT() error {
	_, err := cfg.NativeJWTPolicy()
	return err
}
