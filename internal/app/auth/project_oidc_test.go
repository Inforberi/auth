package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	oidcdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestProjectOIDCDisabled(t *testing.T) {
	for _, name := range []string{"google", "telegram"} {
		svc, err := NewProjectOIDC(t.Context(), projectruntime.Key{}, ProjectOIDCConfig{Provider: name}, ProjectOIDCDependencies{})
		require.NoError(t, err)
		started, err := svc.Start(t.Context(), "")
		require.ErrorIs(t, err, oidcdomain.ErrDisabled)
		require.Nil(t, started)
		callback, err := svc.Callback(t.Context(), oidcservice.CallbackInput{})
		require.ErrorIs(t, err, oidcdomain.ErrDisabled)
		require.Nil(t, callback)
		started, err = svc.StartLink(t.Context(), "", "", "")
		require.ErrorIs(t, err, oidcdomain.ErrDisabled)
		require.Nil(t, started)
		require.ErrorIs(t, svc.Unlink(t.Context(), "", "", ""), oidcdomain.ErrDisabled)
		mfa, err := svc.CompleteMFA(t.Context(), mfaservice.CompleteLoginInput{})
		require.ErrorIs(t, err, mfadomain.ErrUnavailable)
		require.Nil(t, mfa)
	}
	_, err := NewProjectOIDC(t.Context(), projectruntime.Key{}, ProjectOIDCConfig{Provider: "arbitrary"}, ProjectOIDCDependencies{})
	require.ErrorIs(t, err, settingsdomain.ErrInvalidProvider)
}

func TestProjectOIDCConfigAndMFABinding(t *testing.T) {
	owners := NewProjectOIDCClients(t.Context())
	t.Cleanup(owners.Close)
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	deps := ProjectOIDCDependencies{Registry: &projectruntime.Registry{}, Reader: &runtimepostgres.RuntimeCredentialReader{}, Redis: rdb, Clients: owners}
	session := sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}
	mfa := mfaservice.Config{Enabled: true, Issuer: "Project OIDC", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	scope, err := realmscope.New("project", "a9500000-0000-4000-8000-000000000001")
	require.NoError(t, err)
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	for _, name := range []string{"google", "telegram"} {
		cfg := ProjectOIDCConfig{Provider: name, Enabled: true, RedirectURI: "https://project.example.test/api/v1/auth/" + name + "/callback", IPLimit: 30, GlobalLimit: 1000, Session: session, MFA: mfa, Timeout: 10 * time.Second}
		require.NoError(t, cfg.validate(deps))
		cfg.RedirectURI = "https://project.example.test/api/v1/auth/other/callback"
		require.Error(t, cfg.validate(deps))
		factory, err := newProjectMFALogin(scope, root, mfa, session, rdb, name)
		require.NoError(t, err)
		require.True(t, factory.config.AllowPrimary("oidc", settingsdomain.ProviderIssuer(name)))
		require.False(t, factory.config.AllowPrimary("password", ""))
		require.False(t, factory.config.AllowPrimary("emailotp", ""))
		for _, issuer := range []string{settingsdomain.ProviderIssuer("google"), settingsdomain.ProviderIssuer("telegram"), "https://foreign.example.test"} {
			require.Equal(t, issuer == settingsdomain.ProviderIssuer(name), factory.config.AllowPrimary("oidc", issuer))
		}
	}
}
