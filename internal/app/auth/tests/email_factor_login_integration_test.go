package auth_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestEmailFactorLoginSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=true WHERE singleton`)

	t.Run("browser one winner exact assurance and introspection", func(t *testing.T) {
		f := newEmailFactorLoginFixture(t, db, ctx, "browser")
		input := f.start(t, db, ctx)
		var digest, verifier string
		require.NoError(t, db.QueryRow(ctx, `SELECT digest,verifier FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_login'`, f.user).Scan(&digest, &verifier))
		_, err := f.repo.Consume(ctx, digest, verifier)
		require.ErrorIs(t, err, otpdomain.ErrInvalidCode, "second factor must not become email primary authentication")
		_, err = db.Exec(ctx, `UPDATE auth.mfa_login_challenges SET factor_method='totp',factor_email_id=NULL WHERE user_id=$1`, f.user)
		require.Error(t, err, "factor selection must remain bound to the primary challenge")
		job, err := f.repo.ClaimDelivery(ctx)
		require.NoError(t, err)
		require.NotNil(t, job)
		bad := input
		bad.Binding, err = tokengenerate.New().GenerateToken()
		require.NoError(t, err)
		_, err = f.login.Complete(ctx, bad)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		var wg sync.WaitGroup
		results := make(chan *mfalogin.LoginSession, 8)
		for range 8 {
			wg.Go(func() {
				session, err := f.login.Complete(ctx, input)
				if err != nil && !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Error(err)
				}
				results <- session
			})
		}
		wg.Wait()
		close(results)
		var winner *mfalogin.LoginSession
		for session := range results {
			if session != nil {
				require.Nil(t, winner)
				winner = session
			}
		}
		require.NotNil(t, winner)
		stored, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(winner.Token))
		require.NoError(t, err)
		require.Equal(t, mfadomain.EmailCode, stored.MFAMethod)
		require.NotNil(t, stored.MFAVerifiedAt)
		signer, keys := jwtSigningFixture(t)
		tokens := nativeTokenService(t, db, signer)
		scope := []accessdomain.PermissionKey{"orders.read"}
		issued, err := tokens.Exchange(ctx, tokenservice.ExchangeInput{Actor: accessservice.Principal{UserID: f.user, TokenHash: tokengenerate.New().Hash(winner.Token)}, SessionID: string(stored.ID), Audience: "orders", Scope: scope, IP: input.IP})
		require.NoError(t, err)
		verify, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		require.NoError(t, err)
		claims, err := verify.VerifySignature(ctx, issued.Raw, time.Now())
		require.NoError(t, err)
		require.Equal(t, []string{"pwd", "email_otp"}, claims.Methods)
		require.NotNil(t, claims.MFATime)
		_, err = tokenpostgres.New(db).Introspect(ctx, claims, scope)
		require.NoError(t, err)
		forged := claims
		forged.Methods = []string{"pwd", "otp"}
		_, err = tokenpostgres.New(db).Introspect(ctx, forged, scope)
		require.ErrorIs(t, err, authjwt.ErrInvalidToken)
		accessExec(t, db, ctx, `UPDATE auth.mfa_email SET suspended_at=clock_timestamp() WHERE user_id=$1`, f.user)
		_, err = tokenpostgres.New(db).Introspect(ctx, claims, scope)
		require.ErrorIs(t, err, authjwt.ErrInvalidToken)
	})

	t.Run("native rollback and refresh preserve method", func(t *testing.T) {
		f := newEmailFactorLoginFixture(t, db, ctx, "native")
		signer, keys := jwtSigningFixture(t)
		tokens := nativeTokenService(t, db, signer)
		coordinator, err := tokenservice.NewNativeLogin(tokens, f.login)
		require.NoError(t, err)
		started, err := coordinator.Begin(ctx, tokenservice.NativeInput{Proof: f.proof, Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}, IP: "192.0.2.1"})
		require.NoError(t, err)
		require.Nil(t, started.Tokens)
		input := f.code(t, db, ctx, started.Challenge)
		_, err = f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode, "native challenge must not become a browser session")
		accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit ADD CONSTRAINT email_native_failure CHECK(false) NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit DROP CONSTRAINT IF EXISTS email_native_failure`)
		})
		_, err = coordinator.Complete(ctx, input)
		require.Error(t, err)
		var sessions int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND credential_profile='api'`, f.user).Scan(&sessions))
		require.Zero(t, sessions)
		accessExec(t, db, ctx, `ALTER TABLE auth.token_issuance_audit DROP CONSTRAINT email_native_failure`)
		var wg sync.WaitGroup
		results := make(chan *tokenservice.RefreshResult, 6)
		for range 6 {
			wg.Go(func() {
				result, err := coordinator.Complete(ctx, input)
				if err != nil && !errors.Is(err, mfadomain.ErrInvalidCode) {
					t.Error(err)
				}
				results <- result
			})
		}
		wg.Wait()
		close(results)
		var issued *tokenservice.RefreshResult
		for result := range results {
			if result != nil {
				require.Nil(t, issued)
				issued = result
			}
		}
		require.NotNil(t, issued)
		verify, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict}, keys, time.Now())
		require.NoError(t, err)
		before, err := verify.VerifySignature(ctx, issued.Raw, time.Now())
		require.NoError(t, err)
		require.Equal(t, []string{"pwd", "email_otp"}, before.Methods)
		refreshed, err := tokens.Refresh(ctx, tokenservice.RefreshInput{Token: issued.RefreshToken, IP: input.IP})
		require.NoError(t, err)
		after, err := verify.VerifySignature(ctx, refreshed.Raw, time.Now())
		require.NoError(t, err)
		require.Equal(t, before.Methods, after.Methods)
		require.Equal(t, before.MFATime, after.MFATime)
		_, err = coordinator.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
	})

	t.Run("five guesses survive retries", func(t *testing.T) {
		f := newEmailFactorLoginFixture(t, db, ctx, "guesses")
		input := f.start(t, db, ctx)
		correct := input.Code
		input.Code = string('0'+(correct[0]-'0'+1)%10) + correct[1:]
		for range 5 {
			_, err := f.login.Complete(ctx, input)
			require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		}
		input.Code = correct
		_, err := f.login.Complete(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrInvalidCode)
		var attempts, jobs int
		require.NoError(t, db.QueryRow(ctx, `SELECT c.attempts,(SELECT count(*) FROM auth.email_login_outbox o WHERE o.digest=c.digest)
 FROM auth.email_login_challenges c WHERE c.user_id=$1 AND c.purpose='mfa_email_login'`, f.user).Scan(&attempts, &jobs))
		require.Equal(t, 5, attempts)
		require.Zero(t, jobs)
	})

	t.Run("email-only lifecycle respects requirement and strong boundary", func(t *testing.T) {
		f := newEmailFactorLoginFixture(t, db, ctx, "lifecycle")
		loggedIn, err := f.login.Complete(ctx, f.start(t, db, ctx))
		require.NoError(t, err)
		tokens := tokengenerate.New()
		replacement := tokens.Hash("email-lifecycle-password")
		_, err = f.sessions.ConfirmPassword(ctx, f.user, tokens.Hash(loggedIn.Token), "old-hash", f.proof.AuthVersion, replacement)
		require.NoError(t, err)
		proof := mfaservice.Proof{UserID: f.user, TokenHash: replacement, AuthVersion: f.proof.AuthVersion}
		factors, err := mfamanagement.NewEmailFactors(mfapostgres.New(db), f.cipher, mfaTestLimit{})
		require.NoError(t, err)
		_, err = mfaManagement(t, db).RegenerateRecovery(ctx, proof)
		require.ErrorIs(t, err, mfadomain.ErrProofRequired, "email code must not manage strong recovery authority")
		require.ErrorIs(t, factors.Disable(ctx, proof), mfadomain.ErrRequiredByPolicy)
		accessExec(t, db, ctx, `UPDATE auth.roles SET mfa_required=false WHERE id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, f.user)
		require.NoError(t, factors.Disable(ctx, proof))
		var configured bool
		require.NoError(t, db.QueryRow(ctx, `SELECT auth.mfa_login_required($1)`, f.user).Scan(&configured))
		require.False(t, configured)
	})

	t.Run("first TOTP enrollment needs current email factor", func(t *testing.T) {
		f := newEmailFactorLoginFixture(t, db, ctx, "enroll-totp")
		loggedIn, err := f.login.Complete(ctx, f.start(t, db, ctx))
		require.NoError(t, err)
		tokens := tokengenerate.New()
		hash := tokens.Hash("email-first-totp")
		_, err = f.sessions.ConfirmPassword(ctx, f.user, tokens.Hash(loggedIn.Token), "old-hash", f.proof.AuthVersion, hash)
		require.NoError(t, err)
		proof := mfaservice.Proof{UserID: f.user, TokenHash: hash, AuthVersion: f.proof.AuthVersion}
		mfa := mfaManagement(t, db)
		enrollment, err := mfa.StartEnrollment(ctx, proof)
		require.NoError(t, err)
		input := mfamanagement.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET primary_verified_at=clock_timestamp()-interval '7 minutes',mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, hash)
		_, err = mfa.ConfirmEnrollment(ctx, input)
		require.ErrorIs(t, err, mfadomain.ErrProofRequired)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash)
		_, err = mfa.ConfirmEnrollment(ctx, input)
		require.NoError(t, err)
	})

	t.Run("removing TOTP preserves a usable email factor", func(t *testing.T) {
		f, factors := preparedEmailFactor(t, db, ctx, "totp-to-email", true)
		require.NoError(t, factors.Enable(ctx, f.proof))
		proof := renewedEmailFactorProof(t, db, ctx, f.user)
		require.NoError(t, mfaManagement(t, db).Disable(ctx, proof))
		var email, totp bool
		require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1),EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, f.user).Scan(&email, &totp))
		require.True(t, email)
		require.False(t, totp)
		login, err := otpservice.NewEmailLogin(mfapostgres.New(db), f.cipher, recoveryCipher(t), mfaTestLimit{}, tokengenerate.New(), emailFactorLoginConfig())
		require.NoError(t, err)
		e := emailFactorLoginFixture{
			emailPreparationSQLFixture: f, login: login,
			proof: mfaservice.PrimaryProof{UserID: f.user, AuthVersion: proof.AuthVersion + 1, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()},
		}
		_, err = login.Complete(ctx, e.start(t, db, ctx))
		require.NoError(t, err)
	})

	t.Run("optional administrator keeps the available strong factor", func(t *testing.T) {
		f, factors := preparedEmailFactor(t, db, ctx, "admin-strong", true)
		require.NoError(t, factors.Enable(ctx, f.proof))
		accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='optional' WHERE singleton`)
		t.Cleanup(func() { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET mode='administrators' WHERE singleton`) })
		accessExec(t, db, ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('email_admin_fixture','Administrator') RETURNING id),
 p AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM r)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, f.user)
		proof := renewedEmailFactorProof(t, db, ctx, f.user)
		require.ErrorIs(t, mfaManagement(t, db).Disable(ctx, proof), mfadomain.ErrRequiredByPolicy)
	})

	for _, guard := range []string{"suspended", "unverified", "policy", "password", "version", "blocked", "expired", "deleted"} {
		t.Run(guard, func(t *testing.T) {
			f := newEmailFactorLoginFixture(t, db, ctx, guard)
			input := f.start(t, db, ctx)
			switch guard {
			case "suspended":
				accessExec(t, db, ctx, `UPDATE auth.mfa_email SET suspended_at=clock_timestamp() WHERE user_id=$1`, f.user)
			case "unverified":
				accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`, f.user)
			case "policy":
				accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=false WHERE singleton`)
				t.Cleanup(func() {
					accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=true WHERE singleton`)
				})
			case "password":
				accessExec(t, db, ctx, `UPDATE auth.password_credentials SET password_hash='changed' WHERE user_id=$1`, f.user)
			case "version":
				accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, f.user)
			case "blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "expired":
				accessExec(t, db, ctx, `UPDATE auth.mfa_login_challenges SET expires_at=created_at+interval '1 microsecond' WHERE user_id=$1`, f.user)
			case "deleted":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`, f.user)
			}
			_, err := f.login.Complete(ctx, input)
			require.Error(t, err)
			job, err := f.repo.ClaimDelivery(ctx)
			require.NoError(t, err)
			require.Nil(t, job)
		})
	}
}
