package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkTelegramLifecycleGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context, version int64) {
	t.Helper()
	t.Run("only confirmed current source can enable", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "proofs", true)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrInvalidTelegramPreparation)
		other := f.cloneSession(t, db, ctx, "browser")
		_, confirmation := f.begin(t, ctx)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrInvalidTelegramPreparation)
		prepared, err := f.channel.Confirm(ctx, confirmation)
		require.NoError(t, err)
		f.proof.TokenHash = tokengenerate.New().Hash(prepared.Token)
		require.ErrorIs(t, svc.Enable(ctx, other), mfadomain.ErrInvalidTelegramPreparation)
		accessExec(t, db, ctx, `UPDATE auth.mfa_telegram_preparations SET confirmed_at=clock_timestamp(),policy_version=policy_version+1 WHERE user_id=$1`, f.user)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrInvalidTelegramPreparation)
		accessExec(t, db, ctx, `UPDATE auth.mfa_telegram_preparations SET policy_version=$2,created_at=clock_timestamp()-interval '4 minutes',expires_at=clock_timestamp()-interval '1 minute',confirmed_at=clock_timestamp()-interval '2 minutes' WHERE user_id=$1`, f.user, version)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrInvalidTelegramPreparation)
	})
	t.Run("concurrent activation has one winner", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "concurrent", true)
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		activate := func() error { return svc.Enable(ctx, f.proof) }
		a, b := protectionPair(activate, activate)
		if a == nil {
			require.ErrorIs(t, b, mfadomain.ErrProofRequired)
		} else {
			require.NoError(t, b)
			require.ErrorIs(t, a, mfadomain.ErrProofRequired)
		}
	})
	t.Run("disabled policy and stale password cannot enable", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "admission", true)
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=false`)
		t.Cleanup(func() { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=true`) })
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrUnavailable)
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=true`)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET created_at=clock_timestamp()-interval '7 minutes',password_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, f.proof.TokenHash)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrProofRequired)
	})
	t.Run("administrator cannot enroll Telegram without TOTP", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "administrator", false)
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		accessExec(t, db, ctx, `WITH r AS (INSERT INTO auth.roles(key,name) VALUES('telegram_admin','Telegram admin fixture') RETURNING id),
 p AS (INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrProofRequired)
	})
	t.Run("channel cannot be shared by two users", func(t *testing.T) {
		a, first := telegramFactorFixture(t, db, ctx, "owner-a", true)
		b, second := telegramFactorFixture(t, db, ctx, "owner-b", true)
		confirmTelegramFactorChannel(t, ctx, &a, 1<<40)
		require.NoError(t, first.Enable(ctx, a.proof))
		confirmTelegramFactorChannel(t, ctx, &b, 1<<40)
		require.ErrorIs(t, second.Enable(ctx, b.proof), mfadomain.ErrConflict)
	})
	t.Run("audit failure rolls back activation and proof consumption", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "rollback", true)
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_telegram_enable CHECK(event<>'telegram_factor_enabled') NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT IF EXISTS reject_telegram_enable`)
		})
		require.Error(t, svc.Enable(ctx, f.proof))
		_, err := f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		var enabled bool
		require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1)`, f.user).Scan(&enabled))
		require.False(t, enabled)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_telegram_enable`)
		require.NoError(t, svc.Enable(ctx, f.proof), "confirmed preparation remains usable after rollback")
	})
	t.Run("Telegram only requires MFA and cannot become a first TOTP enrollment", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "telegram-only", false)
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		require.NoError(t, svc.Enable(ctx, f.proof))
		var required, usable bool
		require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_login_required($1),auth.mfa_proof_usable($1,'password','telegram')`, f.user).Scan(&required, &usable))
		require.True(t, required)
		require.True(t, usable, "configured Telegram now participates in method-aware proof validation")
		login := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: f.proof.AuthVersion + 1, Method: "password", Reference: "old-hash"}
		login.VerifiedAt = time.Now().UTC()
		tokens := tokengenerate.New()
		challenge, err := mfapostgres.New(db).SaveLoginChallenge(ctx, login, tokens.Hash("telegram-only"), tokens.Hash("telegram-binding"), f.config.TTL)
		require.NoError(t, err)
		require.True(t, challenge.RecoveryRequired)
		require.False(t, challenge.EnrollmentRequired)
		require.ErrorIs(t, svc.Disable(ctx, f.proof), mfadomain.ErrProofRequired)
		require.Error(t, mfapostgres.New(db).CheckCapability(ctx, true))
	})
}
