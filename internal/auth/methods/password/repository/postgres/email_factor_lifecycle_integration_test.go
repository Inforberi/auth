package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func preparedEmailFactor(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string, strong bool) (emailPreparationSQLFixture, *mfaservice.EmailFactors) {
	t.Helper()
	f := newEmailPreparationFixture(t, db, ctx, name, strong)
	prepared, err := f.service.Confirm(ctx, f.request(t, db, ctx))
	require.NoError(t, err)
	f.proof.TokenHash = tokengenerate.New().Hash(prepared.Token)
	svc, err := mfaservice.NewEmailFactors(mfapostgres.New(db), f.cipher, mfaTestLimit{})
	require.NoError(t, err)
	t.Cleanup(func() { accessExec(t, db, ctx, `DELETE FROM auth.mfa_email WHERE user_id=$1`, f.user) })
	return f, svc
}

func renewedEmailFactorProof(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID) mfaservice.Proof {
	t.Helper()
	actor := renewAccessPrincipal(t, db, ctx, user)
	var version int64
	require.NoError(t, db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, user).Scan(&version))
	return mfaservice.Proof{UserID: user, TokenHash: actor.TokenHash, AuthVersion: version}
}

func TestEmailFactorLifecycleSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	actor := mfaTokenPolicyActor(t, db, ctx)
	policy := settingsservice.NewEmailMFA(settingspostgres.New(db), true)
	current, err := policy.Read(ctx, actor)
	require.NoError(t, err)
	require.False(t, current.Allowed)
	change := settingsservice.EmailMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: true}
	_, err = settingsservice.NewEmailMFA(settingspostgres.New(db), false).Update(ctx, change)
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	_, err = settingsservice.NewEmailMFA(settingspostgres.New(db), true).Read(ctx, accessPrincipal(t, db, ctx))
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	current, err = policy.Update(ctx, change)
	require.NoError(t, err)
	require.True(t, current.Allowed)
	_, err = policy.Update(ctx, change)
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
	require.Error(t, mfapostgres.New(db).CheckCapability(ctx, true), "unfinished email runtime must not start")

	t.Run("concurrent activation revokes credentials once", func(t *testing.T) {
		f, svc := preparedEmailFactor(t, db, ctx, "enable", true)
		other := f.cloneSession(t, db, ctx, "browser")
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 6 {
			wg.Go(func() {
				if err := svc.Enable(ctx, f.proof); err == nil {
					winners.Add(1)
				} else if !errors.Is(err, mfadomain.ErrProofRequired) {
					t.Errorf("unexpected activation error: %v", err)
				}
			})
		}
		wg.Wait()
		require.Equal(t, int32(1), winners.Load())
		for _, token := range []string{f.proof.TokenHash, other.TokenHash} {
			_, err := f.sessions.FindSession(ctx, token)
			require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
		}
		proof := renewedEmailFactorProof(t, db, ctx, f.user)
		require.Equal(t, f.proof.AuthVersion+1, proof.AuthVersion)
		state, err := svc.Status(ctx, proof)
		require.NoError(t, err)
		require.True(t, state.Configured)
		require.True(t, state.Usable)
		_, err = policy.Update(ctx, settingsservice.EmailMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: false})
		require.ErrorIs(t, err, settingsdomain.ErrEmailFactorInUse)
		require.ErrorIs(t, mfaManagement(t, db).Disable(ctx, proof), mfadomain.ErrUnavailable, "must keep the only runtime-supported factor")
		require.NoError(t, svc.Disable(ctx, proof))
		_, err = f.sessions.FindSession(ctx, proof.TokenHash)
		require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
		var email, totp bool
		require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, f.user).Scan(&email, &totp))
		require.False(t, email)
		require.True(t, totp)
	})

	t.Run("personal email factor cannot bypass incomplete login", func(t *testing.T) {
		f, svc := preparedEmailFactor(t, db, ctx, "email-only", false)
		require.NoError(t, svc.Enable(ctx, f.proof))
		var required bool
		require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_login_required($1)`, f.user).Scan(&required))
		require.True(t, required)
		params := f.params
		params.AuthVersion = f.proof.AuthVersion + 1
		params.TokenHash = tokengenerate.New().Hash("email-only-unprotected")
		_, err := f.sessions.CreateSession(ctx, params)
		require.ErrorIs(t, err, sessiondomain.ErrMFARequired)
		proof := mfaservice.PrimaryProof{UserID: f.user, AuthVersion: int64(params.AuthVersion), Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()}
		_, err = mfapostgres.New(db).SaveLoginChallenge(ctx, proof, tokengenerate.New().Hash("email-only-challenge"), tokengenerate.New().Hash("email-only-binding"), time.Minute)
		require.ErrorIs(t, err, mfadomain.ErrUnavailable, "must not enter first-TOTP enrollment instead of the enrolled email factor")
		_, err = f.change(ctx, accountdomain.StatusBlocked, accountdomain.AuthVersion(params.AuthVersion))
		require.NoError(t, err)
		_, err = f.change(ctx, accountdomain.StatusActive, accountdomain.AuthVersion(params.AuthVersion+1))
		require.NoError(t, err)
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
		require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_login_required($1)`, f.user).Scan(&required))
		require.True(t, required, "lost mailbox must not silently downgrade to password-only")
	})

	t.Run("fresh preparation and current policy are required", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "no-proof", true)
		svc, err := mfaservice.NewEmailFactors(mfapostgres.New(db), f.cipher, mfaTestLimit{})
		require.NoError(t, err)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrProofRequired)
		prepared, err := f.service.Confirm(ctx, f.request(t, db, ctx))
		require.NoError(t, err)
		f.proof.TokenHash = tokengenerate.New().Hash(prepared.Token)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET email_reauthenticated_at=created_at WHERE token_hash=$1`, f.proof.TokenHash)
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=false WHERE singleton`)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrUnavailable)
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=true WHERE singleton`)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET email_reauthenticated_at=clock_timestamp()-interval '6 minutes',created_at=clock_timestamp()-interval '7 minutes' WHERE token_hash=$1`, f.proof.TokenHash)
		require.ErrorIs(t, svc.Enable(ctx, f.proof), mfadomain.ErrProofRequired)
	})

	t.Run("audit failure rolls activation back", func(t *testing.T) {
		f, svc := preparedEmailFactor(t, db, ctx, "enable-rollback", true)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT email_enable_failure CHECK(event<>'email_factor_enabled') NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT IF EXISTS email_enable_failure`)
		})
		require.Error(t, svc.Enable(ctx, f.proof))
		_, err := f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		var count int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_email WHERE user_id=$1`, f.user).Scan(&count))
		require.Zero(t, count)
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT email_enable_failure`)
		require.NoError(t, svc.Enable(ctx, f.proof))
	})

	t.Run("policy disable and activation serialize", func(t *testing.T) {
		f, svc := preparedEmailFactor(t, db, ctx, "policy-race", true)
		a, b := protectionPair(func() error {
			return svc.Enable(ctx, f.proof)
		}, func() error {
			_, err := policy.Update(ctx, settingsservice.EmailMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: false})
			return err
		})
		if a == nil {
			require.ErrorIs(t, b, settingsdomain.ErrEmailFactorInUse)
		} else {
			require.ErrorIs(t, a, mfadomain.ErrUnavailable)
			require.NoError(t, b)
		}
		var configured, allowed bool
		require.NoError(t, db.QueryRow(ctx, `SELECT email_factor_allowed,EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1) FROM auth.mfa_settings WHERE singleton`, f.user).Scan(&allowed, &configured))
		require.Equal(t, configured, allowed)
		current, err = policy.Read(ctx, actor)
		require.NoError(t, err)
		if !current.Allowed {
			current, err = policy.Update(ctx, settingsservice.EmailMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: true})
			require.NoError(t, err)
		}
	})

	t.Run("mailbox change suspends without rebinding and deletion removes", func(t *testing.T) {
		f, svc := preparedEmailFactor(t, db, ctx, "change", true)
		require.NoError(t, svc.Enable(ctx, f.proof))
		proof := renewedEmailFactorProof(t, db, ctx, f.user)
		state, err := svc.Status(ctx, proof)
		require.NoError(t, err)
		c := changeFixture{statusFixture: f.statusFixture, newEmail: "email-factor-changed@example.test"}
		c.accounts = accountpostgres.NewWithEmailChanges(db)
		c.params.TokenHash = proof.TokenHash
		c.snapshot, err = c.accounts.EmailChangeSnapshot(ctx, c.user)
		require.NoError(t, err)
		tokens := tokengenerate.New()
		c.intent = accountdomain.EmailChangeIntent{
			ConfirmDigest: tokens.Hash("factor-change-confirm"), ReportDigest: tokens.Hash("factor-change-report"),
			RecoveryDigest: tokens.Hash("factor-change-recover"), ConfirmPayload: make([]byte, 32), NoticePayload: make([]byte, 32),
			CompletionPayload: make([]byte, 32), RecoveryPayload: make([]byte, 32), RecoveryTTL: 30 * time.Minute,
			ExpiresAt: time.Now().Add(30 * time.Minute), ProtectUntil: time.Now().Add(24 * time.Hour),
		}
		require.NoError(t, c.request(ctx))
		require.NoError(t, c.accounts.ConfirmEmailChange(ctx, c.intent.ConfirmDigest))
		proof = renewedEmailFactorProof(t, db, ctx, f.user)
		after, err := svc.Status(ctx, proof)
		require.NoError(t, err)
		require.True(t, after.Configured)
		require.Equal(t, state.EmailID, after.EmailID)
		require.NotNil(t, after.SuspendedAt)
		require.False(t, after.Usable)
		_, err = deleteFixture(ctx, f.statusFixture, accountdomain.AuthVersion(proof.AuthVersion))
		require.NoError(t, err)
		var remaining bool
		require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1)`, f.user).Scan(&remaining))
		require.False(t, remaining)
	})

	current, err = policy.Update(ctx, settingsservice.EmailMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: false})
	require.NoError(t, err)
	require.False(t, current.Allowed)
}
