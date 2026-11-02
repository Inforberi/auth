package projects_test

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestTwoProjectEmailOTPHTTPIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	email := prepareEmailIsolation(t, f)
	ctx := t.Context()
	var ciphers [2]*secretbox.Cipher
	for i, key := range f.projects {
		_, err := f.databases[i].Exec(ctx, `UPDATE auth.auth_settings SET email_otp_enabled=true`)
		require.NoError(t, err)
		_, err = f.databases[i].Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
		cfg, err := f.deps.Reader.LoadAuthConfiguration(ctx, key, f.deps.Registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		purpose, err := scope.Purpose("email-login:v1")
		require.NoError(t, err)
		ciphers[i], err = secretbox.NewScoped(cfg.EncryptionKey(), purpose)
		require.NoError(t, err)
		prefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
		require.NoError(t, err)
		keys := []string{"request:ip:127.0.0.1", "request:project", "confirm:ip:127.0.0.1", "confirm:project", "reauth:request:user:" + emailHTTPBindingUser, "reauth:confirm:user:" + emailHTTPBindingUser}
		for _, address := range []string{httpIsolationEmail, "otp-reauth@example.test"} {
			keys = append(keys, "request:email:"+address, "request:cooldown:"+address)
		}
		for _, key := range keys {
			f.redisKeys[prefix+ciphers[i].Digest(key)] = struct{}{}
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, db := range f.databases {
			_, err := db.Exec(cleanup, `DELETE FROM auth.email_login_audit WHERE user_id=ANY($1::uuid[])`, []string{httpIsolationUser, emailHTTPBindingUser})
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.email_login_challenges WHERE user_id=ANY($1::uuid[])`, []string{httpIsolationUser, emailHTTPBindingUser})
			require.NoError(t, err)
		}
	})
	f.deps.Delivery = runEmailHTTPDelivery(t, email)
	cfg := appauth.ProjectEmailOTPConfig{OTP: otpservice.Config{Enabled: true, ReauthenticationEnabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 100, ConfirmGlobalLimit: 1000}, MFA: f.password.MFA, Session: f.password.Session, Timeout: 5 * time.Second}
	webs, handler, _ := f.serve(t, appauth.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, EmailOTP: &cfg, Timeout: 5 * time.Second})
	for i, key := range f.projects {
		require.Eventually(t, func() bool {
			assessment, err := handler.Assess(ctx, key, f.origins[i])
			if err != nil {
				return false
			}
			ready := map[string]bool{}
			for _, feature := range assessment.Features {
				ready[feature.Feature] = feature.Ready
			}
			return ready["emailotp"] && ready["reauthentication"]
		}, 5*time.Second, 20*time.Millisecond)
	}
	checkOTPHTTPLogin(t, email, webs, ciphers)
	checkOTPHTTPReauthentication(t, email, webs, ciphers)
}

func otpHTTPCode(t *testing.T, ctx context.Context, f *emailIsolationFixture, cipher *secretbox.Cipher, project int, cookie, purpose, address string) string {
	t.Helper()
	_, binding, ok := strings.Cut(cookie, "=")
	require.True(t, ok)
	var payload []byte
	require.NoError(t, f.projects.databases[project].QueryRow(ctx, `SELECT payload FROM auth.email_login_outbox WHERE digest=$1`, cipher.Digest(purpose+"binding:"+binding)).Scan(&payload))
	plain, err := cipher.Open(payload)
	require.NoError(t, err)
	defer clear(plain)
	var message struct{ To, Body string }
	require.NoError(t, json.Unmarshal(plain, &message))
	require.Equal(t, address, message.To)
	code := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(message.Body)
	require.Len(t, code, 2)
	return code[1]
}
