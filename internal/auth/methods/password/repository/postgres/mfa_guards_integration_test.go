package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func checkMFARecoveryRace(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *mfaservice.Service, f statusFixture, code string) {
	t.Helper()
	checkMFAOneWinner(t, ctx, svc, mfaservice.VerifyInput{UserID: f.user, AuthVersion: 2, Code: code, Recovery: true})
	var remaining, audits int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1),
		(SELECT count(*) FROM auth.mfa_audit WHERE user_id=$1 AND event='recovery_used')`, f.user).Scan(&remaining, &audits); err != nil || remaining != 9 || audits != 1 {
		t.Fatal("recovery race", remaining, audits, err)
	}
}

func checkMFAOneWinner(t *testing.T, ctx context.Context, svc *mfaservice.Service, input mfaservice.VerifyInput) {
	t.Helper()
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			_, err := svc.Verify(ctx, input)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("expected one factor winner", winners)
	}
}

func checkMFAEnrollmentGuards(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *mfaservice.Service) {
	for _, state := range []string{"blocked", "revoked", "stale-password", "foreign-session"} {
		t.Run(state, func(t *testing.T) {
			f := newStatusFixture(t, db, ctx, "mfa-proof-"+state)
			proof := mfaProof(t, db, ctx, f)
			switch state {
			case "blocked":
				accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
			case "revoked":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, f.user)
			case "stale-password":
				accessExec(t, db, ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '6 minutes' WHERE user_id=$1`, f.user)
			case "foreign-session":
				proof.UserID = f.actor
			}
			if _, err := svc.StartEnrollment(ctx, proof); !errors.Is(err, mfadomain.ErrProofRequired) {
				t.Fatal("invalid proof accepted", err)
			}
		})
	}
	t.Run("attempts-and-expiry", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "mfa-attempts")
		proof := mfaProof(t, db, ctx, f)
		enrollment, err := svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		var digest string
		if err := db.QueryRow(ctx, `SELECT digest FROM auth.mfa_enrollments WHERE user_id=$1`, f.user).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		repo := mfapostgres.New(db)
		invalid := func([]byte, int64, time.Time) (int64, error) { return 0, mfadomain.ErrInvalidCode }
		for range 6 {
			if err := repo.ConfirmEnrollment(ctx, proof, digest, invalid, nil); !errors.Is(err, mfadomain.ErrInvalidCode) {
				t.Fatal(err)
			}
		}
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.mfa_enrollments WHERE user_id=$1`, f.user).Scan(&attempts); err != nil || attempts != 5 {
			t.Fatal("attempt rollback/unbounded", attempts, err)
		}
		if _, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("exhausted enrollment accepted", err)
		}
		enrollment, err = svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `UPDATE auth.mfa_enrollments SET created_at=statement_timestamp()-interval '20 minutes',expires_at=statement_timestamp()-interval '10 minutes' WHERE user_id=$1`, f.user)
		if _, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}); !errors.Is(err, mfadomain.ErrInvalidCode) {
			t.Fatal("expired enrollment accepted", err)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "mfa-rollback")
		proof := mfaProof(t, db, ctx, f)
		enrollment, err := svc.StartEnrollment(ctx, proof)
		if err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_mfa_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
			CREATE TRIGGER reject_mfa_audit BEFORE INSERT ON auth.mfa_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_mfa_audit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_mfa_audit ON auth.mfa_audit; DROP FUNCTION auth.reject_mfa_audit()`)
		})
		if codes, err := svc.ConfirmEnrollment(ctx, mfaservice.ConfirmInput{Proof: proof, Token: enrollment.Token, Code: mfaCode(t, db, ctx, enrollment.Secret, 0)}); err == nil || codes != nil {
			t.Fatal("activation without audit")
		}
		var version accountdomain.AuthVersion
		var enabled bool
		if err := db.QueryRow(ctx, `SELECT auth_version,EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1) FROM auth.users WHERE id=$1`, f.user).Scan(&version, &enabled); err != nil || version != 1 || enabled {
			t.Fatal("partial activation", version, enabled, err)
		}
		if _, err := f.sessions.FindSession(ctx, proof.TokenHash); err != nil {
			t.Fatal("rollback revoked session", err)
		}
	})
}
