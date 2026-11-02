package projects_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func checkEmailChangeIsolation(t *testing.T, ctx context.Context, f *emailIsolationFixture) {
	t.Helper()
	var confirm, report, recovery [2]string
	for i, service := range f.services {
		hash := strings.Repeat("c", 64)
		seedEmailIsolationProof(t, ctx, f.projects.databases[i], httpIsolationUser, hash)
		require.NoError(t, service.RequestEmailChange(ctx, accountdomain.UserID(httpIsolationUser), hash, "isolation-new@example.test", isolationResetPassword, emailIsolationIP))
		for j, kind := range []string{"confirm", "notice"} {
			payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='`+kind+`'`, httpIsolationUser)
			address, recipient := f.configs[i].Change.ConfirmURL, "isolation-new@example.test"
			if j == 1 {
				address, recipient = f.configs[i].Change.ReportURL, httpIsolationEmail
			}
			token := isolationEmailToken(t, f.ciphers[i][0], payload, address, recipient)
			if j == 0 {
				confirm[i] = token
			} else {
				report[i] = token
			}
		}
	}
	for i, service := range f.services {
		require.ErrorIs(t, service.ConfirmEmailChange(ctx, confirm[1-i], emailIsolationIP), accountdomain.ErrInvalidEmailChange)
		require.ErrorIs(t, service.ReportEmailChange(ctx, report[1-i], emailIsolationIP), accountdomain.ErrInvalidEmailChange)
	}
	for i, service := range f.services {
		require.NoError(t, service.ConfirmEmailChange(ctx, confirm[i], emailIsolationIP))
		require.ErrorIs(t, service.ConfirmEmailChange(ctx, confirm[i], emailIsolationIP), accountdomain.ErrInvalidEmailChange)
		var live bool
		const currentProof = `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version WHERE s.user_id=$1 AND s.revoked_at IS NULL)`
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, currentProof, httpIsolationUser).Scan(&live))
		require.False(t, live, "confirmation revokes this project's old proof")
		if i == 0 {
			require.NoError(t, f.projects.databases[1].QueryRow(ctx, currentProof, httpIsolationUser).Scan(&live))
			require.True(t, live, "confirmation in A must preserve B's pending change and proof")
		}
		require.NoError(t, service.ReportEmailChange(ctx, report[i], emailIsolationIP))
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='recovery'`, httpIsolationUser)
		recovery[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Change.RecoveryURL, httpIsolationEmail)
	}
	const peerState = `SELECT jsonb_build_object('user',to_jsonb(u),'credential',to_jsonb(p))::text FROM auth.users u JOIN auth.password_credentials p ON p.user_id=u.id WHERE u.id=$1`
	var peerBefore string
	require.NoError(t, f.projects.databases[1].QueryRow(ctx, peerState, httpIsolationUser).Scan(&peerBefore))
	for i, service := range f.services {
		require.ErrorIs(t, service.RecoverEmailChange(ctx, recovery[1-i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP), accountdomain.ErrInvalidAccountRecovery)
	}
	for i, service := range f.services {
		require.NoError(t, service.RecoverEmailChange(ctx, recovery[i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP))
		require.ErrorIs(t, service.RecoverEmailChange(ctx, recovery[i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP), accountdomain.ErrInvalidAccountRecovery)
		var address, status, hash string
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT e.email,u.status,p.password_hash FROM auth.users u JOIN auth.password_credentials p ON p.user_id=u.id JOIN auth.user_emails e ON e.id=p.email_id WHERE u.id=$1`, httpIsolationUser).Scan(&address, &status, &hash))
		require.Equal(t, httpIsolationEmail, address)
		require.Equal(t, "active", status)
		require.NoError(t, f.projects.deps.Hash.Compare(ctx, httpIsolationPassword, hash))
		if i == 0 {
			var peerAfter string
			require.NoError(t, f.projects.databases[1].QueryRow(ctx, peerState, httpIsolationUser).Scan(&peerAfter))
			require.Equal(t, peerBefore, peerAfter, "recovery in A must preserve pending recovery and credentials in B")
		}
	}
}
