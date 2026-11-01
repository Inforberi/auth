package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func completeEmailMFAAfterRedisFailure(t *testing.T, f emailMFAHTTPFixture, path, cookie, token, binding string, input any) isolationHTTPResponse {
	t.Helper()
	ctx := t.Context()
	key := f.prefix[0] + f.mfa[0].Digest("mfa-email-login:complete:"+token+":"+binding)
	f.projects.redisKeys[key] = struct{}{}
	const stateQuery = `SELECT
 (SELECT count(*) FROM auth.sessions WHERE user_id=$1),
 (SELECT count(*) FROM auth.refresh_families f JOIN auth.sessions s ON s.id=f.session_id WHERE s.user_id=$1),
 (SELECT count(*) FROM auth.refresh_tokens r JOIN auth.sessions s ON s.id=r.session_id WHERE s.user_id=$1),
 (SELECT count(*) FROM auth.token_issuance_audit WHERE user_id=$1),
 (SELECT attempts FROM auth.mfa_login_challenges WHERE user_id=$1),
 (SELECT attempts FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_login')`
	var before [6]int64
	require.NoError(t, f.projects.databases[0].QueryRow(ctx, stateQuery, httpIsolationUser).
		Scan(&before[0], &before[1], &before[2], &before[3], &before[4], &before[5]))
	// Fail the real completion counter, leaving routing and the already-issued challenge intact.
	require.NoError(t, f.projects.deps.Redis.Set(ctx, key, "invalid-counter", time.Minute).Err())
	for range 2 {
		origin := f.webs[0].origin
		if cookie == "" {
			origin = ""
		}
		response := f.webs[0].call(t, ctx, "POST", path, origin, cookie, input)
		require.Equal(t, 503, response.status, string(response.body))
		require.Contains(t, string(response.body), "temporarily_unavailable")
		require.Empty(t, response.cookies)
		for _, secret := range []string{"invalid admission counter", "accessToken", "refreshToken", `"token":`} {
			require.NotContains(t, string(response.body), secret)
		}
		var after [6]int64
		require.NoError(t, f.projects.databases[0].QueryRow(ctx, stateQuery, httpIsolationUser).
			Scan(&after[0], &after[1], &after[2], &after[3], &after[4], &after[5]))
		require.Equal(t, before, after, "failed admission must not consume a challenge, charge SQL guesses or issue credentials")
	}
	require.NoError(t, f.projects.deps.Redis.Del(ctx, key).Err())
	origin := f.webs[0].origin
	if cookie == "" {
		origin = ""
	}
	response := f.webs[0].call(t, ctx, "POST", path, origin, cookie, input)
	require.Equal(t, 200, response.status, string(response.body))
	count, err := f.projects.deps.Redis.Get(ctx, key).Int64()
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "restored admission still charges the completion budget")
	ttl, err := f.projects.deps.Redis.PTTL(ctx, key).Result()
	require.NoError(t, err)
	require.Positive(t, ttl)
	require.LessOrEqual(t, ttl, time.Minute)
	var sessions int64
	require.NoError(t, f.projects.databases[0].QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, httpIsolationUser).Scan(&sessions))
	require.Equal(t, before[0]+1, sessions, "retry creates exactly one session")
	return response
}
