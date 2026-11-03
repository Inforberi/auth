package auth_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
)

func TestMFASecurityNoticesSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=true,telegram_bot_id=123456789`)
	f, factors := telegramFactorFixture(t, db, ctx, "security-notices", true)
	confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_security_outbox ADD CONSTRAINT reject_factor_notice CHECK(notice_kind='recovery') NOT VALID`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_security_outbox DROP CONSTRAINT IF EXISTS reject_factor_notice`)
	})
	require.Error(t, factors.Enable(ctx, f.proof))
	var configured bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1)`, f.user).Scan(&configured))
	require.False(t, configured)
	_, err := f.sessions.FindSession(ctx, f.proof.TokenHash)
	require.NoError(t, err)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_security_outbox DROP CONSTRAINT reject_factor_notice`)
	require.NoError(t, factors.Enable(ctx, f.proof))
	var payload []byte
	var kind string
	require.NoError(t, db.QueryRow(ctx, `SELECT notice_kind,payload FROM auth.mfa_security_outbox WHERE user_id=$1`, f.user).Scan(&kind, &payload))
	require.Equal(t, "telegram_factor_enabled", kind)
	require.False(t, bytes.Contains(payload, []byte(f.email)))
	mail := &recoveryMailer{}
	worker, err := mfadelivery.NewSecurityDelivery(mfapostgres.New(db), f.cipher, mail)
	require.NoError(t, err)
	accessExec(t, db, ctx, `UPDATE auth.user_emails SET email='changed-'||email WHERE user_id=$1`, f.user)
	processed, err := worker.DeliverOne(ctx)
	require.NoError(t, err)
	require.True(t, processed)
	require.Equal(t, f.email, mail.to, "committed recipient snapshot survives contact changes")
	require.Contains(t, mail.body, "Telegram подключён")
	f.proof = renewedEmailFactorProof(t, db, ctx, f.user)
	require.NoError(t, factors.Disable(ctx, f.proof))
	require.NoError(t, db.QueryRow(ctx, `SELECT notice_kind FROM auth.mfa_security_outbox WHERE user_id=$1`, f.user).Scan(&kind))
	require.Equal(t, "telegram_factor_disabled", kind)
	accessExec(t, db, ctx, `UPDATE auth.mfa_security_outbox SET attempts=5,failed_at=clock_timestamp()-interval '2 days' WHERE user_id=$1`, f.user)
	_, err = f.accounts.PurgeRetention(ctx, accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 1, BatchSize: 1})
	require.NoError(t, err)
	var remaining int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_security_outbox WHERE user_id=$1`, f.user).Scan(&remaining))
	require.Zero(t, remaining, "expired dead letters follow security retention in bounded batches")
}
