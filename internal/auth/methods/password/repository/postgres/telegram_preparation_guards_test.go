package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func checkTelegramPreparationGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	for _, tc := range []struct {
		name  string
		query string
		want  error
	}{
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, mfadomain.ErrProofRequired},
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`, mfadomain.ErrProofRequired},
		{"revoked", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, mfadomain.ErrProofRequired},
		{"source token rotation", `UPDATE auth.sessions SET token_hash=repeat('a',64) WHERE user_id=$1`, mfadomain.ErrProofRequired},
		{"password freshness", `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '6 minutes' WHERE user_id=$1`, mfadomain.ErrProofRequired},
		{"intent expiry", `UPDATE auth.mfa_telegram_preparations SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, mfadomain.ErrInvalidTelegramPreparation},
		{"configuration version", `UPDATE auth.mfa_settings SET version=version+1 WHERE singleton AND EXISTS(SELECT 1 FROM auth.users WHERE id=$1)`, mfadomain.ErrUnavailable},
		{"bot identity", `UPDATE auth.mfa_settings SET telegram_bot_id=987654321 WHERE singleton AND EXISTS(SELECT 1 FROM auth.users WHERE id=$1)`, mfadomain.ErrUnavailable},
		{"missing bot configuration", `UPDATE auth.mfa_settings SET telegram_bot_id=NULL WHERE singleton AND EXISTS(SELECT 1 FROM auth.users WHERE id=$1)`, mfadomain.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTelegramPreparationFixture(t, db, ctx, tc.name, false)
			start, input := f.begin(t, ctx)
			accessExec(t, db, ctx, tc.query, f.user)
			_, err := f.channel.Receive(ctx, start)
			require.ErrorIs(t, err, tc.want)
			_, err = f.channel.Confirm(ctx, input)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("native source rejected", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "native", false)
		_, err := f.channel.Request(ctx, f.cloneSession(t, db, ctx, "api"), "192.0.2.1")
		require.ErrorIs(t, err, mfadomain.ErrProofRequired)
	})
	t.Run("required MFA cannot be skipped", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "required", false)
		var previous string
		require.NoError(t, db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings`).Scan(&previous))
		t.Cleanup(func() { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode=$1`, previous) })
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='required'`)
		_, err := f.channel.Request(ctx, f.proof, "192.0.2.1")
		require.ErrorIs(t, err, mfadomain.ErrProofRequired)
	})
}

func checkTelegramPreparationOwnership(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	t.Run("candidate ownership scope and replacement", func(t *testing.T) {
		a := newTelegramPreparationFixture(t, db, ctx, "owner-a", false)
		b := newTelegramPreparationFixture(t, db, ctx, "owner-b", false)
		start, input := a.begin(t, ctx)
		_, err := b.channel.Receive(ctx, start)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation, "another cipher scope cannot resolve this intent")
		changed := start
		changed.TelegramID++
		_, err = a.channel.Receive(ctx, changed)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		changed = start
		changed.UpdateID++
		_, err = a.channel.Receive(ctx, changed)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		second, err := b.channel.Request(ctx, b.proof, "192.0.2.1")
		require.NoError(t, err)
		_, err = b.channel.Receive(ctx, mfaservice.TelegramStart{BotID: b.config.Bot.ID, TelegramID: start.TelegramID, UpdateID: 2, Binding: second.Binding})
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation, "one private channel cannot prepare two users concurrently")
		_, err = a.channel.Request(ctx, a.proof, "192.0.2.1")
		require.NoError(t, err)
		_, err = a.channel.Receive(ctx, start)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		_, err = a.channel.Confirm(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation, "replaced intent must remain unusable")
	})
	t.Run("bounded retention and session cleanup", func(t *testing.T) {
		a := newTelegramPreparationFixture(t, db, ctx, "purge-a", false)
		b := newTelegramPreparationFixture(t, db, ctx, "purge-b", false)
		for _, f := range []telegramPreparationFixture{a, b} {
			_, err := f.channel.Request(ctx, f.proof, "192.0.2.1")
			require.NoError(t, err)
			accessExec(t, db, ctx, `UPDATE auth.mfa_telegram_preparations SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, f.user)
		}
		_, err := a.accounts.PurgeRetention(ctx, accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 1})
		require.NoError(t, err)
		var pending int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_telegram_preparations`).Scan(&pending))
		require.Equal(t, 1, pending, "retention removes at most the configured batch")
		accessExec(t, db, ctx, `DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[])`, []string{string(a.user), string(b.user)})
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_telegram_preparations`).Scan(&pending))
		require.Zero(t, pending)
	})
}
