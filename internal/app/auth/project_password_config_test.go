package auth

import (
	"context"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func TestProjectPasswordConfiguration(t *testing.T) {
	cfg := ProjectPasswordConfig{Timeout: 5 * time.Second, Capacity: passwordservice.CapacityConfig{HashConcurrency: 1, LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 100}, Session: sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}}
	deps := ProjectPasswordDependencies{Registry: &projectruntime.Registry{}, Reader: &runtimepostgres.RuntimeCredentialReader{}, Redis: &redis.Client{}, Hash: &hasher.Bounded{}}
	require.NoError(t, cfg.validate(deps))
	for _, change := range []func(*ProjectPasswordConfig){
		func(c *ProjectPasswordConfig) { c.MFA.Enabled = true },
		func(c *ProjectPasswordConfig) { c.Timeout = 0 }, func(c *ProjectPasswordConfig) { c.Timeout = 31 * time.Second },
		func(c *ProjectPasswordConfig) { c.Capacity.LoginGlobalLimit = 0 }, func(c *ProjectPasswordConfig) { c.Session.SessionTTL = 0 },
	} {
		invalid := cfg
		change(&invalid)
		_, err := NewProjectPassword(t.Context(), projectruntime.Key{}, invalid, deps)
		require.Error(t, err)
	}
	withRecovery := cfg
	withRecovery.MFA = mfaservice.Config{Enabled: true, RecoveryEnabled: true, Issuer: "Fixture", ChallengeTTL: time.Minute, UserLimitPerMinute: 10, IPLimitPerMinute: 10, GlobalLimitPerMinute: 100}
	require.NoError(t, withRecovery.validate(deps), "runtime readiness is checked in the profile, not configuration validation")
	for _, change := range []func(*ProjectPasswordDependencies){
		func(d *ProjectPasswordDependencies) { d.Registry = nil }, func(d *ProjectPasswordDependencies) { d.Reader = nil },
		func(d *ProjectPasswordDependencies) { d.Redis = nil }, func(d *ProjectPasswordDependencies) { d.Hash = nil },
	} {
		invalid := deps
		change(&invalid)
		_, err := NewProjectPassword(t.Context(), projectruntime.Key{}, cfg, invalid)
		require.Error(t, err)
	}
}

func TestProjectMFADisabledFailsClosed(t *testing.T) {
	runtime := &ProjectPassword{}
	session, err := runtime.CompleteMFA(context.Background(), mfalogin.CompleteLoginInput{})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	require.Nil(t, session)
	enrollment, err := runtime.StartMFAEnrollment(context.Background(), mfalogin.LoginEnrollmentInput{})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	require.Nil(t, enrollment)
	codes, err := runtime.ConfirmMFAEnrollment(context.Background(), mfalogin.ConfirmLoginEnrollmentInput{})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	require.Nil(t, codes)
}
