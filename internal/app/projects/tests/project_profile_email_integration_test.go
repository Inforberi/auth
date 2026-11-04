package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/app/projects/delivery"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
)

func (f projectProfileFixture) verificationProfile(t *testing.T, ctx context.Context, origin string) {
	t.Helper()
	_, err := f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=false,google_enabled=false,password_email_verification='optional'`)
	require.NoError(t, err)
	delivery, err := projectdelivery.NewProjectDelivery(projectdelivery.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Second, SMTPAllowedTargets: []string{f.listener.Addr().String()}}, f.deps)
	require.NoError(t, err)
	running, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	joined := false
	go func() { done <- delivery.Run(running, func(error) {}) }()
	t.Cleanup(func() {
		stop()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("profile delivery did not drain")
			}
		}
	})
	cfg := projectprofile.ProjectProfileConfig{Verification: &accountservice.Config{URL: origin + "/verify-email", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100}, Timeout: 10 * time.Second}
	// No password or recovery flow is selected, so no hasher is supplied.
	deps := projectprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb}, Delivery: delivery}
	var profile *projectprofile.ProjectProfile
	var buildErr error
	require.Eventually(t, func() bool {
		profile, buildErr = projectprofile.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
		return buildErr == nil && profile.Readiness().Ready
	}, 3*time.Second, 20*time.Millisecond)
	require.NoError(t, buildErr)
	require.True(t, profileFeature(t, profile, "verification").Ready)
	require.Len(t, profile.RoutePlan(), 2)
	reauthentication := projectprofile.ProjectProfileConfig{
		BrowserEnabled: true,
		EmailOTP: &projectmethods.ProjectEmailOTPConfig{
			OTP:     otpservice.Config{ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000},
			Session: projectPasswordFixtureConfig().Session, Timeout: 5 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
	reauth, err := projectprofile.BuildProjectProfile(ctx, f.key, origin, reauthentication, deps)
	require.NoError(t, err)
	require.True(t, reauth.Readiness().Ready)
	require.True(t, profileFeature(t, reauth, "reauthentication").Ready)
	require.Len(t, reauth.RoutePlan(), 9)
	stop()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		joined = true
	case <-time.After(5 * time.Second):
		t.Fatal("profile delivery did not stop")
	}
	stopped, err := projectprofile.BuildProjectProfile(ctx, f.key, origin, cfg, deps)
	require.NoError(t, err)
	require.False(t, stopped.Readiness().Ready)
	require.Empty(t, stopped.RoutePlan())
	require.Equal(t, "delivery_not_running", profileFeature(t, stopped, "verification").Reason)
}
