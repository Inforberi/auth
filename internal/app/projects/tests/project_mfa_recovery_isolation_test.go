package projects_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestTwoProjectMFARecoverySQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	email := prepareEmailIsolation(t, f)
	f.deps.Delivery = runEmailHTTPDelivery(t, email)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		for _, db := range f.databases {
			_, err := db.Exec(ctx, `DELETE FROM auth.mfa_security_outbox WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
		}
	})
	grantProjectRecoveryOperator(t, pair.admin, f.databases)
	var ciphers [2]*secretbox.Cipher
	for i, key := range f.projects {
		configuration, err := f.deps.Reader.LoadAuthConfiguration(t.Context(), key, f.deps.Registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		purpose, err := scope.Purpose("mfa:v1")
		require.NoError(t, err)
		ciphers[i], err = secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		secret, err := ciphers[i].Seal([]byte(httpIsolationUser + "\x00JBSWY3DPEHPK3PXP"))
		require.NoError(t, err)
		_, err = f.databases[i].Exec(t.Context(), `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, httpIsolationUser, secret)
		require.NoError(t, err)
		_, err = f.databases[i].Exec(t.Context(), `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
		_, err = f.databases[i].Exec(t.Context(), `UPDATE auth.auth_settings SET password_email_verification='disabled',version=version+1`)
		require.NoError(t, err)
	}
	f.password.MFA.RecoveryEnabled = true
	cfg := projectprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, Timeout: 10 * time.Second}
	withoutDelivery := f.deps
	withoutDelivery.Delivery = nil
	profile, err := projectprofile.BuildProjectProfile(t.Context(), f.projects[0], f.origins[0], cfg, withoutDelivery)
	require.NoError(t, err)
	for _, route := range profile.RoutePlan() {
		require.NotEqual(t, "mfa_recovery", route.Feature, "no public recovery without delivery")
	}
	_, err = f.databases[1].Exec(t.Context(), `REVOKE EXECUTE ON FUNCTION auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text) FROM auth_mfa_recovery_operator`)
	require.NoError(t, err)
	profile, err = projectprofile.BuildProjectProfile(t.Context(), f.projects[1], f.origins[1], cfg, f.deps)
	require.NoError(t, err)
	for _, route := range profile.RoutePlan() {
		require.NotEqual(t, "mfa_recovery", route.Feature, "no public recovery without independent operator grants")
	}
	_, err = f.databases[1].Exec(t.Context(), `GRANT EXECUTE ON FUNCTION auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text) TO auth_mfa_recovery_operator`)
	require.NoError(t, err)
	webs, _, _ := f.serve(t, cfg)
	webs[0].trace, webs[1].trace = nil, nil
	challenge := webs[0].call(t, t.Context(), "POST", "/api/v1/auth/login/email", f.origins[0], "", map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword})
	require.Equal(t, 202, challenge.status)
	var login mfaloginhttp.ChallengeResponse
	require.NoError(t, json.Unmarshal(challenge.body, &login))
	cookie := challenge.cookie(t, mfaloginhttp.LoginCookie)
	trackProjectRecoveryLimits(t, &f, ciphers, login.Challenge, cookie)
	start := mfarecoveryhttp.StartRecoveryRequest{Challenge: login.Challenge}
	path := "/api/v1/auth/mfa/recovery/start"
	for _, origin := range []string{"", f.origins[1]} {
		r := webs[0].call(t, t.Context(), "POST", path, origin, cookie, start)
		require.Equal(t, 403, r.status)
	}
	foreign := webs[1].call(t, t.Context(), "POST", path, f.origins[1], cookie, start)
	require.Equal(t, 400, foreign.status, string(foreign.body))
	result := webs[0].call(t, t.Context(), "POST", path, f.origins[0], cookie, start)
	require.Equal(t, 200, result.status, string(result.body))
	var candidate mfarecoveryhttp.RecoveryCandidateResponse
	require.NoError(t, json.Unmarshal(result.body, &candidate))
	require.Equal(t, "operator_approval_required", candidate.Status)
	complete := mfarecoveryhttp.CompleteRecoveryRequest{RequestID: candidate.RequestID, Challenge: login.Challenge, Code: projectMFACode(t, t.Context(), f.databases[0], candidate.Secret, 0)}
	path = "/api/v1/auth/mfa/recovery/complete"
	pending := webs[0].call(t, t.Context(), "POST", path, f.origins[0], cookie, complete)
	require.Equal(t, 400, pending.status, "password and proposed TOTP must not approve recovery")
	var version int64
	require.NoError(t, f.databases[0].QueryRow(t.Context(), `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&version))
	var approved bool
	require.NoError(t, f.databases[0].QueryRow(t.Context(), `SELECT auth.decide_mfa_recovery($1,$2,$3,true,'test','two-project recovery acceptance')`, httpIsolationUser, candidate.RequestID, version).Scan(&approved))
	require.True(t, approved)
	foreign = webs[1].call(t, t.Context(), "POST", path, f.origins[1], cookie, complete)
	require.Equal(t, 400, foreign.status)
	result = webs[0].call(t, t.Context(), "POST", path, f.origins[0], cookie, complete)
	require.Equal(t, 200, result.status, string(result.body))
	var codes mfahttp.RecoveryCodesResponse
	require.NoError(t, json.Unmarshal(result.body, &codes))
	require.Len(t, codes.Codes, 10)
	for _, cookie := range result.cookies {
		require.Negative(t, cookie.MaxAge, "recovery must not create a session")
	}
	replay := webs[0].call(t, t.Context(), "POST", path, f.origins[0], cookie, complete)
	require.Equal(t, 400, replay.status)
	var payload []byte
	require.NoError(t, f.databases[0].QueryRow(t.Context(), `SELECT payload FROM auth.mfa_security_outbox WHERE user_id=$1`, httpIsolationUser).Scan(&payload))
	plain, err := ciphers[0].Open(payload)
	require.NoError(t, err)
	require.Contains(t, string(plain), httpIsolationEmail)
	clear(plain)
	_, err = ciphers[1].Open(payload)
	require.Error(t, err, "a project cannot decrypt another project's notice")
	var otherRequests, otherVersion int64
	require.NoError(t, f.databases[1].QueryRow(t.Context(), `SELECT auth_version,(SELECT count(*) FROM auth.mfa_recovery_requests WHERE user_id=$1) FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&otherVersion, &otherRequests))
	require.Zero(t, otherRequests)
	require.Equal(t, version, otherVersion)
}

func grantProjectRecoveryOperator(t *testing.T, admin *pgx.Conn, databases [2]*pgx.Conn) {
	t.Helper()
	var exists bool
	require.NoError(t, admin.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='auth_mfa_recovery_operator')`).Scan(&exists))
	if !exists {
		_, err := admin.Exec(t.Context(), `CREATE ROLE auth_mfa_recovery_operator NOLOGIN`)
		require.NoError(t, err)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
			defer cancel()
			for _, db := range databases {
				_, err := db.Exec(ctx, `DROP OWNED BY auth_mfa_recovery_operator`)
				require.NoError(t, err)
			}
			_, err := admin.Exec(ctx, `DROP ROLE auth_mfa_recovery_operator`)
			require.NoError(t, err)
		})
	}
	for _, db := range databases {
		_, err := db.Exec(t.Context(), `GRANT USAGE ON SCHEMA auth TO auth_mfa_recovery_operator;
GRANT SELECT(id,status,deleted_at,auth_version) ON auth.users TO auth_mfa_recovery_operator;
GRANT SELECT(user_id,request_id,auth_version,state,expires_at) ON auth.mfa_recovery_requests TO auth_mfa_recovery_operator;
GRANT EXECUTE ON FUNCTION auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text) TO auth_mfa_recovery_operator`)
		require.NoError(t, err)
	}
}

func trackProjectRecoveryLimits(t *testing.T, f *projectIsolationHTTP, ciphers [2]*secretbox.Cipher, token, cookie string) {
	t.Helper()
	binding := strings.TrimPrefix(cookie, mfaloginhttp.LoginCookie+"=")
	for i, key := range f.projects {
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		prefix, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
		require.NoError(t, err)
		for _, purpose := range []string{"recovery-start", "recovery-complete"} {
			f.redisKeys[prefix+"login:"+purpose+":subject:"+ciphers[i].Digest(token+":"+binding)] = struct{}{}
		}
	}
}
