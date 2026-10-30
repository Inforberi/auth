package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (f projectProfileFixture) mfaCapabilityProfile(t *testing.T, ctx context.Context, origin string, deps appauth.ProjectProfileDependencies) {
	t.Helper()
	var previous settingsdomain.MFAMode
	require.NoError(t, f.db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings WHERE singleton`).Scan(&previous))
	var platform settingsdomain.MFASnapshot
	var platformRevision int64
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT version,mode,session_revision FROM auth.mfa_settings WHERE singleton`).Scan(&platform.Version, &platform.Policy.Mode, &platformRevision))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=$1 WHERE singleton`, previous)
		require.NoError(t, err)
	})
	password := projectPasswordFixtureConfig()
	cfg := appauth.ProjectProfileConfig{BrowserEnabled: true, Password: &password, Timeout: 10 * time.Second}
	deps.Redis, deps.Hash = f.rdb, f.hash
	setMode := func(mode settingsdomain.MFAMode) {
		t.Helper()
		_, err := f.db.Exec(ctx, `UPDATE auth.mfa_settings SET mode=$1 WHERE singleton`, mode)
		require.NoError(t, err)
	}
	setMode(settingsdomain.MFAOptional)
	profile, err := appauth.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.True(t, profile.Readiness().Ready, "optional factorless deployment may omit MFA engine")
	setMode(settingsdomain.MFARequired)
	profile, err = appauth.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.Error(t, err, "required policy must reject a deployment unable to complete MFA")
	require.Nil(t, profile, "incompatible deployment must not publish a ready route plan")
	password.MFA = mfaservice.Config{Enabled: true, Issuer: "Project MFA fixture", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	cfg.AuthSettingsEnabled, cfg.RetentionSettingsEnabled, cfg.UserLifecycleEnabled = true, true, true
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFARequired} {
		setMode(mode)
		profile, err = appauth.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
		require.NoError(t, err)
		for _, feature := range []string{"mfa_management", "auth_settings_write", "retention_settings_write", "user_lifecycle"} {
			require.True(t, profileFeature(t, profile, feature).Ready, "%s must depend on engine readiness, not personal enrollment", feature)
		}
	}
	setMode(settingsdomain.MFAOptional)
	password.MFA.Enabled = false
	_, err = f.db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, f.sourceUser, make([]byte, 48))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, f.sourceUser)
		require.NoError(t, err)
	})
	profile, err = appauth.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.Error(t, err, "optional mode must not conceal a personally enrolled factor")
	require.Nil(t, profile)
	var unchanged bool
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT version=$1 AND mode=$2 AND session_revision=$3 FROM auth.mfa_settings WHERE singleton`, platform.Version, platform.Policy.Mode, platformRevision).Scan(&unchanged))
	require.True(t, unchanged, "project policy and factor changes must not mutate platform MFA policy")
}
