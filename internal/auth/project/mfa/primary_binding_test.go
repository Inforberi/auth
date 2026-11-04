package mfa

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestProjectMFAPrimaryBinding(t *testing.T) {
	scope, err := realmscope.New("project", "a9400000-0000-4000-8000-000000000001")
	require.NoError(t, err)
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	cfg := mfaservice.Config{Enabled: true, Issuer: "Project OTP", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	session := sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}
	for _, method := range []string{"password", "emailotp"} {
		factory, err := NewProjectMFALogin(scope, root, cfg, session, rdb, method)
		require.NoError(t, err)
		require.True(t, factory.config.AllowPrimary(method, ""))
		for _, other := range []string{"password", "emailotp", "oidc"} {
			if other != method {
				require.False(t, factory.config.AllowPrimary(other, ""))
			}
		}
		require.False(t, factory.config.AllowPrimary(method, "https://foreign.example.test"))
	}
	for _, name := range []string{"google", "telegram"} {
		factory, err := NewProjectMFALogin(scope, root, cfg, session, rdb, name)
		require.NoError(t, err)
		require.True(t, factory.config.AllowPrimary("oidc", settingsdomain.ProviderIssuer(name)))
		require.False(t, factory.config.AllowPrimary("password", ""))
		require.False(t, factory.config.AllowPrimary("emailotp", ""))
		for _, issuer := range []string{settingsdomain.ProviderIssuer("google"), settingsdomain.ProviderIssuer("telegram"), "https://foreign.example.test"} {
			require.Equal(t, issuer == settingsdomain.ProviderIssuer(name), factory.config.AllowPrimary("oidc", issuer))
		}
	}
	cfg.RecoveryEnabled = true
	require.NoError(t, ValidateProjectMFA(cfg), "recovery routes separately require project SMTP and operator readiness")
}
