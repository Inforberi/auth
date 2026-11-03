package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestProjectEmailOTPDisabled(t *testing.T) {
	service, err := NewProjectEmailOTP(t.Context(), projectruntime.Key{}, ProjectEmailOTPConfig{}, nil, ProjectSMTPDependencies{})
	require.NoError(t, err)
	requested, err := service.Request(t.Context(), "", "")
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, requested)
	session, err := service.Confirm(t.Context(), otpservice.ConfirmInput{})
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, session)
	requested, err = service.RequestReauthentication(t.Context(), mfaservice.Proof{}, "", "")
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, requested)
	reauth, err := service.ConfirmReauthentication(t.Context(), otpservice.ReauthenticationInput{})
	require.ErrorIs(t, err, otpdomain.ErrDisabled)
	require.Nil(t, reauth)
	mfa, err := service.CompleteMFA(t.Context(), mfalogin.CompleteLoginInput{})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	require.Nil(t, mfa)
}

func TestProjectMFAPrimaryBinding(t *testing.T) {
	scope, err := realmscope.New("project", "a9400000-0000-4000-8000-000000000001")
	require.NoError(t, err)
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	cfg := mfaservice.Config{Enabled: true, Issuer: "Project OTP", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	session := sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}
	for _, method := range []string{"password", "emailotp"} {
		factory, err := newProjectMFALogin(scope, root, cfg, session, rdb, method)
		require.NoError(t, err)
		require.True(t, factory.config.AllowPrimary(method, ""))
		for _, other := range []string{"password", "emailotp", "oidc"} {
			if other != method {
				require.False(t, factory.config.AllowPrimary(other, ""))
			}
		}
		require.False(t, factory.config.AllowPrimary(method, "https://foreign.example.test"))
	}
	cfg.RecoveryEnabled = true
	require.NoError(t, validateProjectMFA(cfg), "recovery routes separately require project SMTP and operator readiness")
}
