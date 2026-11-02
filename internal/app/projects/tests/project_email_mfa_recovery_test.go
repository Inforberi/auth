package projects_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

func TestTwoProjectEmailMFARecoveryHTTP(t *testing.T) {
	f := prepareEmailMFAHTTP(t)
	ctx := t.Context()
	web, db := f.webs[0], f.projects.databases[0]
	oldSession := isolationSessionLogin(t, ctx, web)
	neighborSession := isolationSessionLogin(t, ctx, f.webs[1])
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.mfa_security_outbox WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
	})
	// Activation is covered separately; seed the lost-mail state without a TOTP fallback.
	_, err := db.Exec(ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=true`)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.mfa_email(user_id,email_id,enabled_at,suspended_at)
 SELECT user_id,id,statement_timestamp(),statement_timestamp() FROM auth.user_emails WHERE user_id=$1`, httpIsolationUser)
	require.NoError(t, err)
	var totp bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, httpIsolationUser).Scan(&totp))
	require.False(t, totp)
	var neighborVersion int64
	require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&neighborVersion))
	credentials := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", credentials)
	require.Equal(t, 503, response.status, "unavailable selected factor must not silently switch to recovery")
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/recovery/login", web.origin, "", credentials)
	require.Equal(t, 202, response.status, string(response.body))
	var login mfahttp.ChallengeResponse
	require.NoError(t, json.Unmarshal(response.body, &login))
	require.Equal(t, "mfa_recovery_required", login.Status)
	cookie := response.cookie(t, mfahttp.LoginCookie)
	trackProjectRecoveryLimits(t, &f.projects, f.mfa, login.Challenge, cookie)
	start := mfahttp.StartRecoveryRequest{Challenge: login.Challenge}
	startPath := "/api/v1/auth/mfa/recovery/start"
	missingBinding := web.call(t, ctx, "POST", startPath, web.origin, "", start)
	require.Equal(t, 400, missingBinding.status)
	foreign := f.webs[1].call(t, ctx, "POST", startPath, f.webs[1].origin, cookie, start)
	require.Equal(t, 400, foreign.status)
	response = web.call(t, ctx, "POST", startPath, web.origin, cookie, start)
	require.Equal(t, 200, response.status, string(response.body))
	var candidate mfahttp.RecoveryCandidateResponse
	require.NoError(t, json.Unmarshal(response.body, &candidate))
	require.Equal(t, "operator_approval_required", candidate.Status)
	completion := mfahttp.CompleteRecoveryRequest{RequestID: candidate.RequestID, Challenge: login.Challenge, Code: projectMFACode(t, ctx, db, candidate.Secret, 0)}
	completePath := "/api/v1/auth/mfa/recovery/complete"
	pending := web.call(t, ctx, "POST", completePath, web.origin, cookie, completion)
	require.Equal(t, 400, pending.status, "password and a proposed new factor must not authorize recovery")
	var version int64
	require.NoError(t, db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&version))
	decision := mfadomain.RecoveryDecision{UserID: httpIsolationUser, RequestID: candidate.RequestID, ExpectedVersion: version, Approve: true, Environment: "test", Reason: "INC-EMAIL-ONLY"}
	err = f.projects.deps.Registry.UsePool(ctx, f.projects.projects[0], func(ctx context.Context, pool *pgxpool.Pool) error {
		return mfapostgres.New(pool).DecideRecovery(ctx, decision)
	})
	require.ErrorIs(t, err, mfadomain.ErrRecoveryOperatorDenied, "project runtime cannot approve its own recovery")
	var approved bool
	require.NoError(t, db.QueryRow(ctx, `SELECT auth.decide_mfa_recovery($1,$2,$3,$4,$5,$6)`,
		decision.UserID, decision.RequestID, decision.ExpectedVersion, decision.Approve, decision.Environment, decision.Reason).Scan(&approved))
	require.True(t, approved, "approval uses the separate operator connection")
	foreign = f.webs[1].call(t, ctx, "POST", completePath, f.webs[1].origin, cookie, completion)
	require.Equal(t, 400, foreign.status)
	response = web.call(t, ctx, "POST", completePath, web.origin, cookie, completion)
	require.Equal(t, 200, response.status, string(response.body))
	var codes mfahttp.RecoveryCodesResponse
	require.NoError(t, json.Unmarshal(response.body, &codes))
	require.Len(t, codes.Codes, 10)
	for _, cookie := range response.cookies {
		require.Negative(t, cookie.MaxAge, "recovery must not create a session")
	}
	var email bool
	var currentVersion, activeSessions int64
	require.NoError(t, db.QueryRow(ctx, `SELECT auth_version,
 EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),
 EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1),
 (SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)
 FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&currentVersion, &email, &totp, &activeSessions))
	require.Equal(t, version+1, currentVersion)
	require.False(t, email)
	require.True(t, totp)
	require.Zero(t, activeSessions, "recovery revokes old sessions without logging the user in")
	replay := web.call(t, ctx, "POST", completePath, web.origin, cookie, completion)
	require.Equal(t, 400, replay.status)
	isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", oldSession, nil, 401, nil)
	isolationCommand(t, ctx, f.webs[1], "GET", "/api/v1/auth/me", neighborSession, nil, 200, nil)
	var unchanged bool
	require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT auth_version=$2
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_requests WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 FROM auth.users WHERE id=$1`, httpIsolationUser, neighborVersion).Scan(&unchanged))
	require.True(t, unchanged, "recovery must not change the other project")
	response = web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", credentials)
	require.Equal(t, 202, response.status, string(response.body))
	require.NoError(t, json.Unmarshal(response.body, &login))
	require.Equal(t, "mfa_required", login.Status)
	cookie = response.cookie(t, mfahttp.LoginCookie)
	f.trackCompletion(login.Challenge, strings.TrimPrefix(cookie, mfahttp.LoginCookie+"="))
	proof := mfahttp.CompleteLoginRequest{Challenge: login.Challenge, Code: codes.Codes[0], Recovery: true}
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/login/complete", web.origin, cookie, proof)
	require.Equal(t, 200, response.status, string(response.body))
	isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", response.cookie(t, "__Host-session"), nil, 200, nil)
}
