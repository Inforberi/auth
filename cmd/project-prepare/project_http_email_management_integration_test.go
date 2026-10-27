package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func (f projectAccountFixture) httpAccountManagement(t *testing.T, ctx context.Context, management appauth.ProjectEmailConfig, temporary passwordservice.TemporaryPasswordConfig) (projectAccountRequest, string, func()) {
	t.Helper()
	var origin string
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, f.key.Binding.ProjectID).Scan(&origin))
	management.Origin = origin
	management.Invitations.URL = origin + "/activate"
	management.Change.ConfirmURL, management.Change.ReportURL, management.Change.RecoveryURL = origin+"/change-email", origin+"/protect-account", origin+"/recover-account"
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}})
	require.NoError(t, err)
	password := projectPasswordFixtureConfig()
	password.TemporaryPassword = temporary
	password.MFA = mfaservice.Config{Enabled: true, Issuer: "Project", ChallengeTTL: time.Minute, UserLimitPerMinute: 30, IPLimitPerMinute: 50, GlobalLimitPerMinute: 100}
	otp := appauth.ProjectEmailOTPConfig{OTP: otpservice.Config{ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000}, MFA: password.MFA, Session: password.Session, Timeout: 5 * time.Second}
	delivery, err := appauth.NewProjectDelivery(appauth.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Minute, SMTPAllowedTargets: []string{f.listener.Addr().String()}}, f.deps)
	require.NoError(t, err)
	running, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- delivery.Run(running, func(error) {}) }()
	joined := false
	stopDelivery := func() {
		stop()
		if joined {
			return
		}
		select {
		case err := <-done:
			joined = true
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Error("email management delivery did not drain")
		}
	}
	t.Cleanup(stopDelivery)
	handler, err := appauth.NewProjectHTTP(appauth.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-account.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 20 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &password.Session,
	}, appauth.ProjectProfileDependencies{ProjectTokenDependencies: appauth.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, Hash: f.hash}, Delivery: delivery}, func(_ context.Context, key projectruntime.Key, selected string) (appauth.ProjectProfileConfig, error) {
		require.Equal(t, f.key, key)
		require.Equal(t, origin, selected)
		return appauth.ProjectProfileConfig{BrowserEnabled: true, UserLifecycleEnabled: true, AuthSettingsEnabled: true, Access: &catalog, Password: &password, EmailOTP: &otp, EmailManagement: &management, Timeout: 10 * time.Second}, nil
	}, nil)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		assessment, err := handler.Assess(ctx, f.key, origin)
		if err != nil {
			return false
		}
		ready := 0
		for _, feature := range assessment.Features {
			if feature.Ready && (feature.Feature == "email_binding" || feature.Feature == "email_change" || feature.Feature == "provisioning" || feature.Feature == "invitation_activation" || feature.Feature == "temporary_password_admin" || feature.Feature == "user_lifecycle" || feature.Feature == "access_read" || feature.Feature == "access_write" || feature.Feature == "auth_settings_read" || feature.Feature == "auth_settings_write") {
				ready++
			}
		}
		return ready == 10
	}, 5*time.Second, 20*time.Millisecond)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	host, err := url.Parse(origin)
	require.NoError(t, err)
	for _, path := range []string{"/api/v1/auth/email/change/confirm", "/api/v1/auth/invitations/activate"} {
		r, err := http.NewRequestWithContext(ctx, "GET", server.URL+path+"?token=not-consumed", nil)
		require.NoError(t, err)
		r.Host = host.Host
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		require.Equal(t, 405, response.StatusCode, "opening an email link must not activate or confirm")
		require.NoError(t, response.Body.Close())
	}
	return func(method, path, requestOrigin, raw, body string) (int, []*http.Cookie, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		r.Host = host.Host
		r.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if raw != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: raw})
		}
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		return response.StatusCode, response.Cookies(), payload
	}, origin, stopDelivery
}
