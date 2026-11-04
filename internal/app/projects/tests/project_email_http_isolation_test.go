package projects_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	profilefactory "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

const emailHTTPBindingUser = "f8b00000-0000-4000-8000-000000000001"

func TestTwoProjectEmailHTTPIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	projects := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	f := prepareEmailIsolation(t, projects)
	webs := serveEmailHTTPIsolation(t, f)
	ctx := t.Context()
	owners := [2]string{isolationAdminLogin(t, ctx, webs[0], httpOwnerEmail), isolationAdminLogin(t, ctx, webs[1], httpOwnerEmail)}
	checkEmailHTTPVerificationReset(t, ctx, f, webs)
	checkEmailHTTPProvisioning(t, ctx, f, webs, owners)
	checkEmailHTTPChange(t, ctx, f, webs)
	checkEmailHTTPBinding(t, ctx, f, webs, owners)
}

func serveEmailHTTPIsolation(t *testing.T, f *emailIsolationFixture) [2]isolationHTTP {
	t.Helper()
	ctx := t.Context()
	trackEmailHTTPLimits(t, f)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, db := range f.projects.databases {
			_, err := db.Exec(cleanup, `DELETE FROM auth.email_bindings WHERE user_id=$1`, emailHTTPBindingUser)
			require.NoError(t, err)
		}
	})
	for _, db := range f.projects.databases {
		_, err := db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'accounts.email.bind' FROM auth.roles WHERE key='super_admin'`)
		require.NoError(t, err)
	}
	delivery := runEmailHTTPDelivery(t, f)
	deps := f.projects.deps
	deps.Delivery = delivery
	password := f.projects.password
	password.TemporaryPassword = passwordprovisioning.TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Second, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
	otp := projectmethods.ProjectEmailOTPConfig{OTP: otpservice.Config{ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000}, MFA: password.MFA, Session: password.Session, Timeout: 5 * time.Second}
	var management [2]projectaccount.ProjectEmailConfig
	for i := range management {
		management[i] = f.configs[i]
		management[i].Binding = accountemail.EmailBindingConfig{Enabled: true, TTL: 5 * time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000}
	}
	handler, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{PlatformOrigin: "https://platform-http.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &password.Session}, deps.Reader, profilefactory.NewFactory(deps,
		func(_ context.Context, key projectruntime.Key, origin string) (runtimeprofile.ProjectProfileConfig, error) {
			for i, expected := range f.projects.projects {
				if key == expected && origin == f.projects.origins[i] {
					return runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &password, Verification: &management[i].Verification, Recovery: &management[i].Password, EmailManagement: &management[i], EmailOTP: &otp, Timeout: 5 * time.Second}, nil
				}
			}
			return runtimeprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
		}), nil)
	require.NoError(t, err)
	for i, key := range f.projects.projects {
		require.Eventually(t, func() bool {
			assessment, err := handler.Assess(ctx, key, f.projects.origins[i])
			if err != nil {
				return false
			}
			ready := map[string]bool{}
			for _, feature := range assessment.Features {
				ready[feature.Feature] = feature.Ready
			}
			for _, name := range []string{"password", "verification", "recovery", "reauthentication", "email_binding", "email_binding_confirmation", "email_change", "email_change_protection", "provisioning", "invitation_activation", "temporary_password", "temporary_password_admin"} {
				if !ready[name] {
					return false
				}
			}
			return true
		}, 5*time.Second, 20*time.Millisecond)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	return [2]isolationHTTP{{server: server, origin: f.projects.origins[0]}, {server: server, origin: f.projects.origins[1]}}
}

func emailHTTPLogin(t *testing.T, ctx context.Context, web isolationHTTP, email, password string) string {
	t.Helper()
	response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", map[string]string{"email": email, "password": password})
	require.Equal(t, 200, response.status, "%s", response.body)
	return response.cookie(t, "__Host-session")
}

func requireNoEmailLoginCookie(t *testing.T, response isolationHTTPResponse) {
	t.Helper()
	for _, cookie := range response.cookies {
		require.Empty(t, cookie.Value, "email completion must not issue login credentials")
	}
}
