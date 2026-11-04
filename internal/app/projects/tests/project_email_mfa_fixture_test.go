package projects_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/app/projects/browser"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type emailMFAHTTPFixture struct {
	projects projectIsolationHTTP
	tokens   tokenIsolationFixture
	webs     [2]isolationHTTP
	mail     [2]*secretbox.Cipher
	mfa      [2]*secretbox.Cipher
	channel  [2]*secretbox.Cipher
	prefix   [2]string
	config   projectmfa.ProjectEmailMFAConfig
}

func prepareEmailMFAHTTP(t *testing.T) emailMFAHTTPFixture { return prepareMFAHTTP(t, nil) }

func prepareMFAHTTP(t *testing.T, bot projectmfa.ProjectTelegramClient) emailMFAHTTPFixture {
	t.Helper()
	pair := prepareHTTPProjects(t)
	projects := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	email := prepareEmailIsolation(t, projects)
	projects.deps.Delivery = runEmailHTTPDelivery(t, email)
	projects.deps.BotAPI = bot
	grantProjectRecoveryOperator(t, pair.admin, projects.databases)
	projects.password.MFA.RecoveryEnabled = true
	if bot != nil {
		projects.password.MFA.UserLimitPerMinute = 100
		projects.password.MFA.IPLimitPerMinute = 100
		projects.password.MFA.GlobalLimitPerMinute = 1000
	}

	tokens := prepareTokenIsolation(t, projects)
	projects = tokens.projects
	f := emailMFAHTTPFixture{projects: projects, tokens: tokens}
	for i, key := range projects.projects {
		_, err := projects.databases[i].Exec(t.Context(), `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
		_, err = projects.databases[i].Exec(t.Context(), `UPDATE auth.auth_settings SET password_email_verification='disabled',version=version+1`)
		require.NoError(t, err)
		configuration, err := projects.deps.Reader.LoadAuthConfiguration(t.Context(), key, projects.deps.Registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		for purpose, target := range map[string]**secretbox.Cipher{"email-login:v1": &f.mail[i], "mfa:v1": &f.mfa[i], "telegram-channel:v1": &f.channel[i]} {
			name, err := scope.Purpose(purpose)
			require.NoError(t, err)
			*target, err = secretbox.NewScoped(configuration.EncryptionKey(), name)
			require.NoError(t, err)
		}
		f.prefix[i], err = scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
		require.NoError(t, err)
	}
	f.trackLimits(t)
	config := projectmfa.ProjectEmailMFAConfig{Preparation: otpservice.EmailPreparationConfig{TTL: 3 * time.Minute, ResendInterval: time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 100}, Factors: mfamanagement.EmailFactorConfig{UserMutationsPerMinute: 5, ProjectMutationsPerMinute: 500}}
	f.config = config
	deployment := loadEmailMFADeployment(t, f, []string{email.listeners[0].Addr().String(), email.listeners[1].Addr().String()})
	source := deployment.Profile
	if bot != nil {
		source = func(ctx context.Context, key projectruntime.Key, origin string) (projectprofile.ProjectProfileConfig, error) {
			config, err := deployment.Profile(ctx, key, origin)
			config.TelegramMFA = true
			config.MFASettingsEnabled = true
			return config, err
		}
	}
	handler, err := projectbrowser.NewProjectHTTP(projectprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute},
		Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &projects.password.Session,
	}, projects.deps, source, nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(ctx))
		for _, db := range projects.databases {
			if bot != nil {
				for _, query := range []string{
					`DELETE FROM auth.mfa_telegram_preparations WHERE user_id=$1`,
					`DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`,
					`DELETE FROM auth.mfa_telegram WHERE user_id=$1`,
					`DELETE FROM auth.mfa_preferences WHERE user_id=$1`,
					`DELETE FROM auth.mfa_security_outbox WHERE user_id=$1`,
				} {
					_, err := db.Exec(ctx, query, httpIsolationUser)
					require.NoError(t, err)
				}
				_, err := db.Exec(ctx, `DELETE FROM auth.telegram_bot_settings_audit WHERE actor_id=$1`, httpOwnerID)
				require.NoError(t, err)
				_, err = db.Exec(ctx, `DELETE FROM auth.mfa_audit WHERE user_id=$1`, httpOwnerID)
				require.NoError(t, err)
				_, err = db.Exec(ctx, `DELETE FROM auth.telegram_bot_settings; UPDATE auth.mfa_settings SET telegram_factor_allowed=false,telegram_bot_id=NULL`)
				require.NoError(t, err)
			}

			_, err := db.Exec(ctx, `DELETE FROM auth.mfa_settings_audit WHERE actor_id=$1`, httpOwnerID)
			require.NoError(t, err)
			_, err = db.Exec(ctx, `DELETE FROM auth.mfa_audit WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(ctx, `DELETE FROM auth.mfa_email WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(ctx, `DELETE FROM auth.email_login_audit WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=false WHERE singleton`)
			require.NoError(t, err)
		}
	})
	for i := range f.webs {
		f.webs[i] = isolationHTTP{server: server, origin: projects.origins[i]}
	}
	return f
}

func (f emailMFAHTTPFixture) code(t *testing.T, purpose, binding string) string {
	t.Helper()
	var encrypted []byte
	err := f.projects.databases[0].QueryRow(t.Context(), `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, f.mail[0].Digest(purpose+"binding:"+binding)).Scan(&encrypted)
	require.NoError(t, err)
	plain, err := f.mail[0].Open(encrypted)
	require.NoError(t, err)
	defer clear(plain)
	var message struct{ Body string }
	require.NoError(t, json.Unmarshal(plain, &message))
	match := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(message.Body)
	require.Len(t, match, 2)
	return match[1]
}

func (f emailMFAHTTPFixture) trackLimits(t *testing.T) {
	t.Helper()
	f.projects.trackLogin(httpOwnerEmail)
	for i := range f.projects.projects {
		for _, user := range []string{httpOwnerID, httpIsolationUser} {
			f.projects.redisKeys[f.projects.passwordPrefix[i]+f.projects.passwordCipher[i].Digest("reauth-user:"+user)] = struct{}{}
		}
		for _, phase := range []string{"request", "confirm"} {
			for _, suffix := range []string{":ip:127.0.0.1", ":user:" + httpIsolationUser, ":project", ":cooldown:" + httpIsolationUser} {
				f.projects.redisKeys[f.projects.passwordPrefix[i]+f.mail[i].Digest("mfa-email-prepare:"+phase+suffix)] = struct{}{}
			}
		}
		for _, logical := range []string{"email-factor:user:" + httpIsolationUser, "email-factor:project", "mfa-email-login:resend:" + httpIsolationUser} {
			f.projects.redisKeys[f.prefix[i]+f.mfa[i].Digest(logical)] = struct{}{}
		}
	}
}

func (f emailMFAHTTPFixture) trackCompletion(token, binding string) {
	for i := range f.projects.projects {
		for _, logical := range []string{"mfa-email-login:complete:" + token + ":" + binding, "login:complete:subject:"} {
			key := f.mfa[i].Digest(logical)
			if logical == "login:complete:subject:" {
				key = logical + f.mfa[i].Digest(token+":"+binding)
			}
			f.projects.redisKeys[f.prefix[i]+key] = struct{}{}
		}
	}
}
