package postgres

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestEmailFactorPreparationSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	t.Run("purpose isolation and one-time session rotation", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "normal", true)
		input := f.request(t, db, ctx)
		before, err := f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		job, err := f.repo.ClaimDelivery(ctx)
		require.NoError(t, err)
		require.NotNil(t, job)
		login := otpdomain.Challenge{Digest: tokengenerate.New().Hash("independent-login"), Verifier: tokengenerate.New().Hash("login-code"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(5 * time.Minute)}
		require.NoError(t, f.repo.Issue(ctx, f.email, login))
		_, err = f.repo.Consume(ctx, f.cipher.Digest(preparationPurpose+"binding:"+input.Binding), f.cipher.Digest(preparationPurpose+"code:"+input.Binding+":"+input.Code))
		require.ErrorIs(t, err, otpdomain.ErrInvalidCode)
		_, err = f.repo.ConfirmEmailPreparation(ctx, f.proof, login.Digest, login.Verifier, tokengenerate.New().Hash("wrong-purpose"))
		require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		other := f.cloneSession(t, db, ctx, "browser")
		foreign := input
		foreign.Proof = other
		_, err = f.service.Confirm(ctx, foreign)
		require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		var attempts int
		require.NoError(t, db.QueryRow(ctx, `SELECT attempts FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_prepare'`, f.user).Scan(&attempts))
		require.Zero(t, attempts)
		var winner *otpservice.ReauthenticatedSession
		var mu sync.Mutex
		var winners atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				result, err := f.service.Confirm(ctx, input)
				if err != nil {
					if !errors.Is(err, mfadomain.ErrProofRequired) && !errors.Is(err, otpdomain.ErrInvalidPreparation) {
						t.Error(err)
					}
					return
				}
				winners.Add(1)
				mu.Lock()
				winner = result
				mu.Unlock()
			})
		}
		wg.Wait()
		require.Equal(t, int32(1), winners.Load())
		require.NotNil(t, winner)
		newHash := tokengenerate.New().Hash(winner.Token)
		_, err = f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.Error(t, err)
		after, err := f.sessions.FindSession(ctx, newHash)
		require.NoError(t, err)
		require.Equal(t, before.ID, after.ID)
		require.Equal(t, before.ExpiresAt, after.ExpiresAt)
		require.Equal(t, before.AbsoluteExpiresAt, after.AbsoluteExpiresAt)
		require.Equal(t, before.AuthVersion, after.AuthVersion)
		require.Equal(t, before.MFAMethod, after.MFAMethod)
		require.Equal(t, before.MFAVerifiedAt, after.MFAVerifiedAt)
		var prepared, privateUnchanged bool
		require.NoError(t, db.QueryRow(ctx, `SELECT email_reauthenticated_at IS NOT NULL,
 password_verified_at=(SELECT password_verified_at FROM auth.sessions WHERE token_hash=$2)
 FROM auth.sessions WHERE token_hash=$1`, newHash, other.TokenHash).Scan(&prepared, &privateUnchanged))
		require.True(t, prepared)
		require.True(t, privateUnchanged)
		_, err = f.sessions.FindSession(ctx, other.TokenHash)
		require.NoError(t, err)
		input.Proof.TokenHash = newHash
		_, err = f.service.Confirm(ctx, input)
		require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		_, err = f.repo.Consume(ctx, login.Digest, login.Verifier)
		require.NoError(t, err)
	})
	t.Run("request ownership deadline and replacement", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "replacement", true)
		_, err := f.service.Request(ctx, f.proof, "unowned@example.test", "192.0.2.1")
		require.ErrorIs(t, err, mfadomain.ErrProofRequired)
		var count int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_challenges WHERE user_id=$1`, f.user).Scan(&count))
		require.Zero(t, count)
		var passwordTime time.Time
		require.NoError(t, db.QueryRow(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '4 minutes' WHERE token_hash=$1 RETURNING password_verified_at`, f.proof.TokenHash).Scan(&passwordTime))
		first := f.request(t, db, ctx)
		second := f.request(t, db, ctx)
		var expires time.Time
		require.NoError(t, db.QueryRow(ctx, `SELECT expires_at FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_prepare'`, f.user).Scan(&expires))
		require.True(t, expires.Equal(passwordTime.Add(5*time.Minute)))
		_, err = f.service.Confirm(ctx, first)
		require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		_, err = f.service.Confirm(ctx, second)
		require.NoError(t, err)
	})
	t.Run("optional password account does not gain MFA", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "optional", false)
		result, err := f.service.Confirm(ctx, f.request(t, db, ctx))
		require.NoError(t, err)
		session, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(result.Token))
		require.NoError(t, err)
		require.Nil(t, session.MFAVerifiedAt)
		require.Empty(t, session.MFAMethod)
		var factors int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1`, f.user).Scan(&factors))
		require.Zero(t, factors)
	})
	t.Run("five failed guesses persist", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "attempts", true)
		input := f.request(t, db, ctx)
		correct := input.Code
		input.Code = string('0'+(correct[0]-'0'+1)%10) + correct[1:]
		for range 5 {
			_, err := f.service.Confirm(ctx, input)
			require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		}
		input.Code = correct
		_, err := f.service.Confirm(ctx, input)
		require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
		var attempts, jobs int
		require.NoError(t, db.QueryRow(ctx, `SELECT c.attempts,(SELECT count(*) FROM auth.email_login_outbox o WHERE o.digest=c.digest)
 FROM auth.email_login_challenges c WHERE c.user_id=$1 AND c.purpose='mfa_email_prepare'`, f.user).Scan(&attempts, &jobs))
		require.Equal(t, 5, attempts)
		require.Zero(t, jobs)
	})
	for _, guard := range []string{"unverified", "blocked", "version", "revoked", "password-stale", "password-missing", "unknown-mfa", "expired", "email-primary", "oidc-primary", "native"} {
		t.Run(guard, func(t *testing.T) {
			f := newEmailPreparationFixture(t, db, ctx, guard, true)
			input := f.request(t, db, ctx)
			switch guard {
			case "unverified":
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
			case "blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "version":
				input.Proof.AuthVersion++
			case "revoked":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, f.proof.TokenHash)
			case "password-stale":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, f.proof.TokenHash)
			case "password-missing":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=NULL WHERE token_hash=$1`, f.proof.TokenHash)
			case "unknown-mfa":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_method=NULL WHERE token_hash=$1`, f.proof.TokenHash)
			case "expired":
				accessExec(t, db, ctx, `UPDATE auth.email_login_challenges SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, f.user)
			case "email-primary":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_method='emailotp' WHERE token_hash=$1`, f.proof.TokenHash)
			case "oidc-primary":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_method='oidc' WHERE token_hash=$1`, f.proof.TokenHash)
			case "native":
				input.Proof = f.cloneSession(t, db, ctx, "api")
			}
			if guard != "version" && guard != "native" {
				job, err := f.repo.ClaimDelivery(ctx)
				require.NoError(t, err)
				require.Nil(t, job)
			}
			result, err := f.service.Confirm(ctx, input)
			require.Nil(t, result)
			require.Error(t, err)
			if guard == "unverified" || guard == "expired" {
				require.ErrorIs(t, err, otpdomain.ErrInvalidPreparation)
			} else {
				require.ErrorIs(t, err, mfadomain.ErrProofRequired)
			}
		})
	}
	t.Run("audit failure rolls back rotation and consumption", func(t *testing.T) {
		f := newEmailPreparationFixture(t, db, ctx, "rollback", true)
		input := f.request(t, db, ctx)
		accessExec(t, db, ctx, `ALTER TABLE auth.email_login_audit ADD CONSTRAINT preparation_audit_failure CHECK(event<>'email_factor_prepared') NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.email_login_audit DROP CONSTRAINT IF EXISTS preparation_audit_failure`)
		})
		result, err := f.service.Confirm(ctx, input)
		require.Nil(t, result)
		require.Error(t, err)
		_, err = f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.NoError(t, err)
		accessExec(t, db, ctx, `ALTER TABLE auth.email_login_audit DROP CONSTRAINT preparation_audit_failure`)
		_, err = f.service.Confirm(ctx, input)
		require.NoError(t, err)
	})
}
