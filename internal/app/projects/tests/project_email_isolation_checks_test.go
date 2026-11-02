package projects_test

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

const isolationResetPassword = "Isolated-reset-password-89!"

func checkEmailVerificationResetIsolation(t *testing.T, ctx context.Context, f *emailIsolationFixture) {
	t.Helper()
	var verification, reset [2]string
	for i, service := range f.services {
		seedEmailIsolationProof(t, ctx, f.projects.databases[i], httpIsolationUser, strings.Repeat(string(rune('8'+i)), 64))
		require.NoError(t, service.ResendVerification(ctx, httpIsolationEmail, emailIsolationIP))
		require.NoError(t, service.ForgotPassword(ctx, httpIsolationEmail, emailIsolationIP))
		v := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_verification_outbox o JOIN auth.email_verifications v USING(digest) WHERE v.email_id IN(SELECT id FROM auth.user_emails WHERE user_id=$1)`, httpIsolationUser)
		r := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.password_reset_outbox o JOIN auth.password_resets r USING(digest) WHERE r.user_id=$1`, httpIsolationUser)
		verification[i] = isolationEmailToken(t, f.ciphers[i][0], v, f.configs[i].Verification.URL, httpIsolationEmail)
		reset[i] = isolationEmailToken(t, f.ciphers[i][1], r, f.configs[i].Password.ResetURL, httpIsolationEmail)
		_, err := f.ciphers[1-i][0].Open(v)
		require.Error(t, err, "other project cannot decrypt the queued verification")
		_, err = f.ciphers[1-i][1].Open(r)
		require.Error(t, err, "other project cannot decrypt the queued reset")
		_, err = f.ciphers[i][1].Open(v)
		require.Error(t, err, "same project must retain purpose separation")
	}
	require.NotEqual(t, verification[0], verification[1])
	require.NotEqual(t, reset[0], reset[1])
	checkEmailIsolationRetries(t, ctx, f)
	for i, service := range f.services {
		require.ErrorIs(t, service.ConfirmVerification(ctx, verification[1-i], emailIsolationIP), accountdomain.ErrInvalidVerification)
		require.ErrorIs(t, service.ResetPassword(ctx, reset[1-i], isolationResetPassword, isolationResetPassword, emailIsolationIP), passworddomain.ErrInvalidReset)
		require.ErrorIs(t, service.ConfirmVerification(ctx, reset[i], emailIsolationIP), accountdomain.ErrInvalidVerification)
		require.ErrorIs(t, service.ResetPassword(ctx, verification[i], isolationResetPassword, isolationResetPassword, emailIsolationIP), passworddomain.ErrInvalidReset)
		var untouched bool
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT e.verified_at IS NULL AND u.auth_version=1
 FROM auth.users u JOIN auth.user_emails e ON e.user_id=u.id WHERE u.id=$1`, httpIsolationUser).Scan(&untouched))
		require.True(t, untouched)
	}
	for i, service := range f.services {
		require.NoError(t, service.ConfirmVerification(ctx, verification[i], emailIsolationIP))
		require.ErrorIs(t, service.ConfirmVerification(ctx, verification[i], emailIsolationIP), accountdomain.ErrInvalidVerification)
		require.NoError(t, service.ResetPassword(ctx, reset[i], isolationResetPassword, isolationResetPassword, emailIsolationIP))
		require.ErrorIs(t, service.ResetPassword(ctx, reset[i], isolationResetPassword, isolationResetPassword, emailIsolationIP), passworddomain.ErrInvalidReset)
		var verified bool
		var hash string
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT e.verified_at IS NOT NULL,p.password_hash FROM auth.user_emails e JOIN auth.password_credentials p ON p.email_id=e.id WHERE p.user_id=$1`, httpIsolationUser).Scan(&verified, &hash))
		require.True(t, verified)
		require.NoError(t, f.projects.deps.Hash.Compare(ctx, isolationResetPassword, hash))
		var live bool
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version WHERE s.user_id=$1 AND s.revoked_at IS NULL)`, httpIsolationUser).Scan(&live))
		require.False(t, live, "own reset revokes the pre-existing session")
		if i == 0 {
			var peerHash string
			require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id=$1`, httpIsolationUser).Scan(&peerHash))
			require.NoError(t, f.projects.deps.Hash.Compare(ctx, httpIsolationPassword, peerHash), "A reset must preserve B credentials")
			require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version WHERE s.user_id=$1 AND s.revoked_at IS NULL)`, httpIsolationUser).Scan(&live))
			require.True(t, live, "A reset must preserve B's existing proof")
		}
	}
}

func isolationEmailPayload(t *testing.T, ctx context.Context, db *pgx.Conn, query string, user any) []byte {
	t.Helper()
	var payload []byte
	require.NoError(t, db.QueryRow(ctx, query, user).Scan(&payload))
	return payload
}

func isolationEmailToken(t *testing.T, cipher *secretbox.Cipher, payload []byte, expectedURL, recipient string) string {
	t.Helper()
	plain, err := cipher.Open(payload)
	require.NoError(t, err)
	defer clear(plain)
	var message struct{ To, Link, Body string }
	require.NoError(t, json.Unmarshal(plain, &message))
	require.Equal(t, recipient, message.To)
	content := message.Link + " " + message.Body
	require.Contains(t, content, expectedURL)
	match := regexp.MustCompile(`[#?&]token=([A-Za-z0-9_-]{43})`).FindStringSubmatch(content)
	require.Len(t, match, 2)
	return match[1]
}
