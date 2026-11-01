package postgres

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestTelegramChannelPreparationSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	t.Run("source session rotation without new authority", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "normal", false)
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
		before, err := f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		start, input := f.begin(t, ctx)
		redelivery, err := f.channel.Receive(ctx, start)
		require.NoError(t, err)
		require.Equal(t, input.Code, redelivery.Code, "duplicate update must preserve the original verifier/code")
		foreign := input
		foreign.Proof = f.cloneSession(t, db, ctx, "browser")
		_, err = f.channel.Confirm(ctx, foreign)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		var attempts int
		require.NoError(t, db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_telegram_preparations WHERE user_id=$1`, f.user).Scan(&attempts))
		require.Zero(t, attempts, "another session must not charge this intent's guessing budget")
		prepared, err := f.channel.Confirm(ctx, input)
		require.NoError(t, err)
		require.EqualValues(t, 1<<40, prepared.TelegramID)
		_, err = f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.Error(t, err)
		after, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(prepared.Token))
		require.NoError(t, err)
		require.Equal(t, before.ID, after.ID)
		require.Equal(t, before.AuthVersion, after.AuthVersion)
		require.Equal(t, before.ExpiresAt, after.ExpiresAt)
		require.Equal(t, before.AbsoluteExpiresAt, after.AbsoluteExpiresAt)
		require.Equal(t, before.MFAMethod, after.MFAMethod)
		require.Equal(t, before.MFAVerifiedAt, after.MFAVerifiedAt)
		input.Proof.TokenHash = tokengenerate.New().Hash(prepared.Token)
		_, err = f.channel.Confirm(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		_, err = f.channel.Receive(ctx, start)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		var clean bool
		require.NoError(t, db.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL AND payload IS NULL AND verifier IS NULL
 AND session_hash=$2 AND (SELECT password_verified_at FROM auth.sessions WHERE token_hash=$2)=
 (SELECT password_verified_at FROM auth.sessions WHERE token_hash=$3)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1)
 FROM auth.mfa_telegram_preparations WHERE user_id=$1`, f.user, input.Proof.TokenHash, foreign.Proof.TokenHash).Scan(&clean))
		require.True(t, clean)
	})
	t.Run("guesses persist and delivery cannot reset them", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "guesses", false)
		start, input := f.begin(t, ctx)
		valid := input
		input.Code = "00000000"
		if input.Code == valid.Code {
			input.Code = "00000001"
		}
		for range 5 {
			_, err := f.channel.Confirm(ctx, input)
			require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		}
		_, err := f.channel.Confirm(ctx, valid)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		_, err = f.channel.Receive(ctx, start)
		require.ErrorIs(t, err, mfadomain.ErrInvalidTelegramPreparation)
		var attempts int
		require.NoError(t, db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_telegram_preparations WHERE user_id=$1`, f.user).Scan(&attempts))
		require.Equal(t, 5, attempts)
	})
	t.Run("single winner", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "race", true)
		_, input := f.begin(t, ctx)
		var winners atomic.Int32
		var workers sync.WaitGroup
		for range 6 {
			workers.Go(func() {
				_, err := f.channel.Confirm(ctx, input)
				if err == nil {
					winners.Add(1)
				} else if !errors.Is(err, mfadomain.ErrProofRequired) && !errors.Is(err, mfadomain.ErrInvalidTelegramPreparation) {
					t.Error(err)
				}
			})
		}
		workers.Wait()
		require.Equal(t, int32(1), winners.Load())
	})
	t.Run("audit rollback preserves the source and intent", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "rollback", false)
		_, input := f.begin(t, ctx)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_telegram_confirmation CHECK(event<>'telegram_channel_confirmed') NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT IF EXISTS reject_telegram_confirmation`)
		})
		_, err := f.channel.Confirm(ctx, input)
		require.Error(t, err)
		_, err = f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_telegram_confirmation`)
		_, err = f.channel.Confirm(ctx, input)
		require.NoError(t, err)
	})
	checkTelegramPreparationGuards(t, db, ctx)
	checkTelegramPreparationOwnership(t, db, ctx)
}
