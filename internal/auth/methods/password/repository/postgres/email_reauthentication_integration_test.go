package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatotp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func emailProofFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) (statusFixture, *otppostgres.Repository, mfaservice.Proof, otpdomain.Challenge) {
	t.Helper()
	f, repo, c := otpSQLFixture(t, db, ctx, "reauth-"+name)
	if _, err := db.Exec(ctx, `DELETE FROM auth.password_credentials WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES ($1,'https://accounts.google.com',$2)`, f.user, string(f.user)); err != nil {
		t.Fatal(err)
	}
	return f, repo, mfaservice.Proof{UserID: f.user, AuthVersion: 1, TokenHash: f.params.TokenHash}, c
}

func checkEmailReauthentication(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("one-winner-purpose-lifetime", func(t *testing.T) {
		f, repo, proof, c := emailProofFixture(t, db, ctx, "race")
		if err := repo.IssueReauthentication(ctx, proof, f.email, c); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("reauth code accepted for login", err)
		}
		job, err := repo.ClaimDelivery(ctx)
		if err != nil || job == nil {
			t.Fatal("external-only proof not deliverable", err)
		}
		var wins atomic.Int64
		var wg sync.WaitGroup
		replacement := tokengenerate.New().Hash("reauth-replacement-" + string(f.user))
		for range 16 {
			wg.Go(func() {
				result, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, replacement)
				if err == nil {
					wins.Add(1)
					if !result.ExpiresAt.Equal(f.params.ExpiresAt.Truncate(time.Microsecond)) {
						t.Error("lifetime extended", result.ExpiresAt)
					}
				} else if !errors.Is(err, mfadomain.ErrProofRequired) && !errors.Is(err, otpdomain.ErrInvalidCode) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatal("completion winners", wins.Load())
		}
		var password, mfa *time.Time
		var email *time.Time
		if err := db.QueryRow(ctx, `SELECT password_verified_at,mfa_verified_at,email_reauthenticated_at FROM auth.sessions WHERE token_hash=$1`, replacement).Scan(&password, &mfa, &email); err != nil || password != nil || mfa != nil || email == nil {
			t.Fatal("wrong authority", err, password, mfa, email)
		}
		proof.TokenHash = replacement
		if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, tokengenerate.New().Hash("replay")); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("replay", err)
		}
		var outbox int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_outbox WHERE digest=$1`, c.Digest).Scan(&outbox); err != nil || outbox != 0 {
			t.Fatal("outbox survived", err, outbox)
		}
	})
	t.Run("foreign-session-and-committed-attempts", func(t *testing.T) {
		f, repo, proof, c := emailProofFixture(t, db, ctx, "attempts")
		if err := repo.IssueReauthentication(ctx, proof, f.email, c); err != nil {
			t.Fatal(err)
		}
		params := f.params
		params.TokenHash = tokengenerate.New().Hash("other-session-" + string(f.user))
		if _, err := f.sessions.CreateSession(ctx, params); err != nil {
			t.Fatal(err)
		}
		foreign := proof
		foreign.TokenHash = params.TokenHash
		if _, err := repo.ConfirmReauthentication(ctx, foreign, c.Digest, c.Verifier, tokengenerate.New().Hash("foreign")); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal(err)
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.email_login_challenges WHERE digest=$1`, c.Digest).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatal("foreign session burned guesses", attempts, err)
		}
		for range 5 {
			if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, tokengenerate.New().Hash("wrong"), tokengenerate.New().Hash("unused")); !errors.Is(err, otpdomain.ErrInvalidCode) {
				t.Fatal(err)
			}
		}
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.email_login_challenges WHERE digest=$1`, c.Digest).Scan(&attempts); err != nil || attempts != 5 {
			t.Fatal("failed attempts rolled back", err, attempts)
		}
		if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, tokengenerate.New().Hash("exhausted")); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal(err)
		}
	})
	for _, guard := range []string{"unverified", "foreign-email", "stale-version", "blocked", "revoked", "password", "expired-challenge", "rotated", "audit-failure"} {
		t.Run(guard, func(t *testing.T) {
			f, repo, proof, c := emailProofFixture(t, db, ctx, guard)
			if err := repo.IssueReauthentication(ctx, proof, f.email, c); err != nil {
				t.Fatal(err)
			}
			var query string
			switch guard {
			case "unverified":
				query = `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`
			case "foreign-email":
				if err := repo.IssueReauthentication(ctx, proof, "attacker@example.test", c); !errors.Is(err, mfadomain.ErrProofRequired) {
					t.Fatal(err)
				}
				return
			case "stale-version":
				query = `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`
			case "blocked":
				query = `UPDATE auth.users SET status='blocked' WHERE id=$1`
			case "revoked":
				query = `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`
			case "password":
				query = `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT user_id,id,'added-password' FROM auth.user_emails WHERE user_id=$1`
			case "expired-challenge":
				query = `UPDATE auth.email_login_challenges SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE user_id=$1`
			case "rotated":
				if _, err := db.Exec(ctx, `UPDATE auth.sessions SET token_hash=$2 WHERE user_id=$1`, f.user, tokengenerate.New().Hash("reauth-rotated-"+string(f.user))); err != nil {
					t.Fatal(err)
				}
			case "audit-failure":
				if _, err := db.Exec(ctx, `ALTER TABLE auth.email_login_audit ADD CONSTRAINT reauth_audit_failure CHECK (event<>'email_reauthenticated') NOT VALID`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := db.Exec(ctx, `ALTER TABLE auth.email_login_audit DROP CONSTRAINT reauth_audit_failure`); err != nil {
						t.Error(err)
					}
				})
			}
			if query != "" {
				if _, err := db.Exec(ctx, query, f.user); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, tokengenerate.New().Hash("rejected-"+guard)); err == nil {
				t.Fatal("guard bypassed", guard)
			}
			if guard == "audit-failure" {
				var count int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE token_hash=$1 AND email_reauthenticated_at IS NULL`, proof.TokenHash).Scan(&count); err != nil || count != 1 {
					t.Fatal("session mutation survived rollback", err, count)
				}
				if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_challenges WHERE digest=$1`, c.Digest).Scan(&count); err != nil || count != 1 {
					t.Fatal("code consumed despite audit failure", err, count)
				}
			}
		})
	}
	t.Run("mfa-enrollment-and-freshness", func(t *testing.T) {
		f, repo, proof, c := emailProofFixture(t, db, ctx, "enrollment")
		if err := repo.IssueReauthentication(ctx, proof, f.email, c); err != nil {
			t.Fatal(err)
		}
		replacement := tokengenerate.New().Hash("enrollment-mail-proof")
		if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, replacement); err != nil {
			t.Fatal(err)
		}
		proof.TokenHash = replacement
		cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
		if err != nil {
			t.Fatal(err)
		}
		svc := mfaservice.New(mfapostgres.NewWithEmailProof(db, true), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, "Auth")
		if _, err := mfaService(t, db).StartEnrollment(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("disabled email policy bypass", err)
		}
		if _, err := svc.StartReplacement(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("mail proof replaced factor without MFA", err)
		}
		if err := svc.Disable(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("mail proof disabled MFA", err)
		}
		if _, err := svc.RegenerateRecovery(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("mail proof regenerated codes", err)
		}
		enrollment, err := svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		// Make the session old enough for an expired proof to satisfy the schema invariant.
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET created_at=clock_timestamp()-interval '10 minutes',email_reauthenticated_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, proof.TokenHash); err != nil {
			t.Fatal(err)
		}
		input := mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}
		if _, err := svc.ConfirmEnrollment(ctx, input); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("expired email proof accepted", err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET email_reauthenticated_at=clock_timestamp() WHERE token_hash=$1`, proof.TokenHash); err != nil {
			t.Fatal(err)
		}
		codes, err := svc.ConfirmEnrollment(ctx, input)
		if err != nil || len(codes.Codes) != 10 {
			t.Fatal(err, codes)
		}
		if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err == nil {
			t.Fatal("enrollment did not revoke session")
		}
		login, err := mfaservice.NewLogin(mfapostgres.New(db), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.LoginConfig{
			ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour,
			UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
		})
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := login.Start(ctx, mfaservice.PrimaryProof{
			UserID: f.user, AuthVersion: 2, Method: "oidc",
			Issuer: "https://accounts.google.com", Reference: string(f.user), VerifiedAt: time.Now().UTC(),
		}, "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		session, err := login.Complete(ctx, mfaservice.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: codes.Codes[0], Recovery: true, IP: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		proof = mfaservice.Proof{UserID: f.user, AuthVersion: 2, TokenHash: tokengenerate.New().Hash(session.Token)}
		if err := repo.IssueReauthentication(ctx, proof, f.email, c); err != nil {
			t.Fatal(err)
		}
		proofReplacement := tokengenerate.New().Hash("email-proof-after-oidc-" + string(f.user))
		if _, err := repo.ConfirmReauthentication(ctx, proof, c.Digest, c.Verifier, proofReplacement); err != nil {
			t.Fatal(err)
		}
		proof.TokenHash = proofReplacement
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET primary_verified_at=clock_timestamp()-interval '10 minutes',
			mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, proof.TokenHash); err != nil {
			t.Fatal(err)
		}
		management, err := mfaservice.NewConfigured(mfapostgres.NewWithEmailProof(db, true), cipher, mfatotp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), mfaservice.Config{
			Enabled: true, Issuer: "Auth", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 500,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := management.RegenerateRecovery(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
			t.Fatal("email proof refreshed old MFA", err)
		}
		step, err := management.StepUp(ctx, mfaservice.StepUpInput{Proof: proof, Code: codes.Codes[1], Recovery: true})
		if err != nil {
			t.Fatal(err)
		}
		proof.TokenHash = tokengenerate.New().Hash(step.Token)
		regenerated, err := management.RegenerateRecovery(ctx, proof)
		if err != nil || len(regenerated.Codes) != 10 {
			t.Fatal("external-only management", err, regenerated)
		}
		if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err == nil {
			t.Fatal("management did not revoke external-only session")
		}
	})
}
