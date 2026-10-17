package config

import (
	"strings"
	"testing"
	"time"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
)

func nativeJWTConfig() Config {
	cfg := validConfig()
	cfg.JWT = tokensettings.Config{
		Enabled: true, NativeEnabled: true, Issuer: "https://auth.example", SigningKeyID: "synthetic",
		PrivateKeyFile: "private.pem", KeySetFile: "jwks.json", ResourceFile: "resources.json",
		AccessTTL: 2 * time.Minute, RefreshIdleTTL: time.Hour, RefreshAbsoluteTTL: 2 * time.Hour,
		ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 40,
	}
	cfg.MFA = mfaservice.Config{Enabled: true, Issuer: "Auth", ChallengeTTL: time.Minute, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500}
	return cfg
}

func TestNativeJWTDeployment(t *testing.T) {
	cfg := nativeJWTConfig()
	if err := cfg.ValidateDeployment(); err != nil {
		t.Fatal(err)
	}
	before := cfg
	policy, err := cfg.NativeJWTPolicy()
	if err != nil || policy == nil || policy.IdleTTL != cfg.JWT.RefreshIdleTTL || policy.AbsoluteTTL != cfg.JWT.RefreshAbsoluteTTL || policy.Sessions != cfg.Session {
		t.Fatal("policy not assembled", policy, err)
	}
	if cfg.JWT != before.JWT || cfg.Retention != before.Retention || cfg.Session != before.Session {
		t.Fatal("deployment budgets or lifetimes were changed automatically")
	}
	cfg.Session.AdminIdleTimeout = time.Minute
	if policy.Sessions.AdminIdleTimeout != before.Session.AdminIdleTimeout {
		t.Fatal("native policy aliases mutable deployment")
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"JWT disabled", func(c *Config) { c.JWT.Enabled = false }, "JWT_ENABLED"},
		{"MFA disabled", func(c *Config) { c.MFA.Enabled = false }, "MFA_ENABLED"},
		{"idle absent", func(c *Config) { c.JWT.RefreshIdleTTL = 0 }, "JWT_REFRESH_IDLE_TTL"},
		{"idle exceeds session", func(c *Config) { c.JWT.RefreshIdleTTL = c.Session.SessionTTL + time.Second }, "SESSION_TTL"},
		{"absolute exceeds session", func(c *Config) { c.JWT.RefreshAbsoluteTTL = c.Session.AbsoluteSessionTTL + time.Second }, "ABSOLUTE_SESSION_TTL"},
		{"absolute below idle", func(c *Config) { c.JWT.RefreshAbsoluteTTL = time.Minute }, "JWT_REFRESH_ABSOLUTE_TTL"},
		{"subsecond idle", func(c *Config) { c.JWT.RefreshIdleTTL -= time.Nanosecond }, "whole seconds"},
		{"subsecond absolute", func(c *Config) { c.JWT.RefreshAbsoluteTTL -= time.Nanosecond }, "whole seconds"},
		{"admin bounds", func(c *Config) { c.Session.AdminActivityInterval = c.Session.AdminIdleTimeout }, "admin session"},
		{"default issuance mismatch", func(c *Config) { c.JWT.ProjectPerMinute = 3000 }, "cleanup budget mismatch"},
		{"invalid cleanup", func(c *Config) { c.Retention.Interval = 0 }, "retention batch"},
		{"large budgets do not overflow", func(c *Config) { c.JWT.ProjectPerMinute = 1_000_000; c.Retention.Interval = time.Hour }, "cleanup budget mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := before
			test.change(&candidate)
			if policy, err := candidate.NativeJWTPolicy(); policy != nil || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatal("incompatible native deployment accepted", policy, err)
			}
			if err := candidate.ValidateDeployment(); err == nil {
				t.Fatal("startup skipped native deployment guard")
			}
		})
	}
}

func TestNativeJWTCleanupHeadroom(t *testing.T) {
	for _, test := range []struct {
		name           string
		project, batch int
		interval       time.Duration
		allowed        bool
	}{
		{"default cleanup within reserve", 46, 100, time.Minute, true},
		{"default cleanup exceeds reserve", 47, 100, time.Minute, false},
		{"exact reserve", 60, 130, time.Minute, true},
		{"one nanosecond below reserve", 60, 130, time.Minute + time.Nanosecond, false},
		{"explicit high issuance", 3000, 600, time.Second, true},
		{"one row below reserve", 3000, 599, time.Second, false},
		{"batch cannot compensate slow interval", 3000, 1000, time.Minute, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := nativeJWTConfig()
			cfg.JWT.ProjectPerMinute, cfg.Retention.BatchSize, cfg.Retention.Interval = test.project, test.batch, test.interval
			policy, err := cfg.NativeJWTPolicy()
			if test.allowed != (err == nil && policy != nil) {
				t.Fatal("wrong cleanup headroom", policy, err)
			}
		})
	}
}

func TestNativeJWTDisabledIsIndependent(t *testing.T) {
	cfg := nativeJWTConfig()
	cfg.JWT.NativeEnabled = false
	cfg.JWT.RefreshIdleTTL, cfg.JWT.RefreshAbsoluteTTL = 0, 0
	cfg.JWT.ProjectPerMinute = 3000
	cfg.MFA.Enabled = false
	if err := cfg.ValidateDeployment(); err != nil {
		t.Fatal("cookie exchange acquired native prerequisites", err)
	}
	if policy, err := cfg.NativeJWTPolicy(); policy != nil || err != nil {
		t.Fatal("disabled native still configured", policy, err)
	}
}
