package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func projectMFADrill(t *testing.T, admin, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, cfg appauth.ProjectPasswordConfig, deps appauth.ProjectPasswordDependencies, input passwordservice.LoginInput) {
	t.Helper()
	ctx := t.Context()
	cfg.MFA = mfaservice.Config{Enabled: true, Issuer: "Project MFA fixture", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("mfa:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	keys := map[string]struct{}{}
	for _, name := range []string{cipher.Digest("user:" + passwordFixtureUser), cipher.Digest("login:factor-user:" + passwordFixtureUser), "login:ip:" + cipher.Digest(input.IP), "project"} {
		keys[prefix+name] = struct{}{}
	}
	track := func(purpose, token, binding string) {
		keys[prefix+"login:"+purpose+":subject:"+cipher.Digest(token+":"+binding)] = struct{}{}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		known := make([]string, 0, len(keys))
		for key := range keys {
			known = append(known, key)
		}
		require.NoError(t, rdb.Del(cleanup, known...).Err())
		_, err := db.Exec(cleanup, `DELETE FROM auth.mfa_audit WHERE user_id=$1;
  DELETE FROM auth.mfa_login_challenges WHERE user_id=$1; DELETE FROM auth.mfa_enrollments WHERE user_id=$1;
  DELETE FROM auth.sessions WHERE user_id=$1 AND mfa_verified_at IS NOT NULL;
  DELETE FROM auth.mfa_totp WHERE user_id=$1;
  DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN(SELECT id FROM auth.roles WHERE key='project_password_fixture_mfa');
  DELETE FROM auth.roles WHERE key='project_password_fixture_mfa'`, passwordFixtureUser)
		require.NoError(t, err)
	})
	var clean bool
	require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1) AND NOT EXISTS(SELECT 1 FROM auth.roles WHERE key='project_password_fixture_mfa')`, passwordFixtureUser).Scan(&clean))
	require.True(t, clean)
	_, err = db.Exec(ctx, `WITH r AS(INSERT INTO auth.roles(key,name,mfa_required) VALUES('project_password_fixture_mfa','Project MFA',true) RETURNING id) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, passwordFixtureUser)
	require.NoError(t, err)
	svc, err := appauth.NewProjectPassword(ctx, key, cfg, deps)
	require.NoError(t, err)
	countSessions := func() int {
		var n int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, passwordFixtureUser).Scan(&n))
		return n
	}
	start := func() *mfaservice.LoginChallenge {
		before := countSessions()
		result, err := svc.Login(ctx, input)
		require.NoError(t, err)
		require.Empty(t, result.Token)
		require.NotNil(t, result.Challenge)
		require.Equal(t, before, countSessions())
		return result.Challenge
	}
	complete := func(challenge *mfaservice.LoginChallenge, code string, recovery bool) (*mfaservice.LoginSession, error) {
		track("complete", challenge.Token, challenge.Binding)
		return svc.CompleteMFA(ctx, mfaservice.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: code, Recovery: recovery, UserAgent: input.UserAgent, IP: input.IP})
	}
	codeAt := func(secret string, offset time.Duration) string {
		return projectMFACode(t, ctx, db, secret, offset)
	}
	restricted := start()
	require.True(t, restricted.EnrollmentRequired)
	before := countSessions()
	result, err := complete(restricted, strings.Repeat("a", 32), true)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, result)
	require.Equal(t, before, countSessions())
	enrollmentInput := mfaservice.LoginEnrollmentInput{Challenge: restricted.Token, Binding: restricted.Binding, IP: input.IP}
	track("enrollment", restricted.Token, restricted.Binding)
	enrollment, err := svc.StartMFAEnrollment(ctx, enrollmentInput)
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Secret)
	require.NotEmpty(t, enrollment.URI)
	codes, err := svc.ConfirmMFAEnrollment(ctx, mfaservice.ConfirmLoginEnrollmentInput{LoginEnrollmentInput: enrollmentInput, Token: enrollment.Token, Code: codeAt(enrollment.Secret, 0)})
	require.NoError(t, err)
	require.Len(t, codes.Codes, 10)
	require.Equal(t, before, countSessions(), "enrollment never creates a normal session")
	// Enabling a factor revokes previous proofs/challenges; the user must authenticate again.
	result, err = complete(restricted, codes.Codes[0], true)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, result)
	challenge := start()
	require.False(t, challenge.EnrollmentRequired)
	wrongBinding := *challenge
	wrongBinding.Binding = strings.Repeat("A", 43)
	result, err = complete(&wrongBinding, codes.Codes[0], true)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, result)
	require.Equal(t, before, countSessions())
	result, err = complete(challenge, codes.Codes[0], true)
	require.NoError(t, err)
	require.NotEmpty(t, result.Token)
	require.False(t, result.MFAVerified.IsZero())
	require.Equal(t, before+1, countSessions())
	var verified bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions WHERE token_hash=$1 AND user_id=$2 AND mfa_verified_at IS NOT NULL)`, tokengenerate.New().Hash(result.Token), passwordFixtureUser).Scan(&verified))
	require.True(t, verified)
	result, err = complete(challenge, codes.Codes[0], true)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, result)
	require.Equal(t, before+1, countSessions())
	challenge = start()
	result, err = complete(challenge, codeAt(enrollment.Secret, 30*time.Second), false)
	require.NoError(t, err)
	require.NotEmpty(t, result.Token)
	require.Equal(t, before+2, countSessions())
	challenge = start()
	result, err = complete(challenge, codes.Codes[0], true)
	require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	require.Nil(t, result)
	require.Equal(t, before+2, countSessions())
	// Restricted completion, enrollment confirmation and three factor checks exhaust the fixed user budget.
	result, err = complete(challenge, codes.Codes[1], true)
	require.ErrorIs(t, err, mfadomain.ErrLimited)
	require.Nil(t, result)
	require.Equal(t, before+2, countSessions())
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=$1 AND digest=$2)`, passwordFixtureUser, cipher.Digest("recovery:"+passwordFixtureUser+":"+codes.Codes[1])).Scan(&verified))
	require.True(t, verified, "rate rejection must not consume an unused recovery code")
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, key.Binding.ProjectID, key.Version)
		require.NoError(t, err)
	})
	result, err = complete(challenge, codes.Codes[1], true)
	require.ErrorIs(t, err, projectdomain.ErrConflict)
	require.Nil(t, result)
}

func projectMFACode(t *testing.T, ctx context.Context, db *pgx.Conn, secret string, offset time.Duration) string {
	t.Helper()
	var now time.Time
	require.NoError(t, db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now))
	code, err := totp.GenerateCode(secret, now.Add(offset))
	require.NoError(t, err)
	return code
}
