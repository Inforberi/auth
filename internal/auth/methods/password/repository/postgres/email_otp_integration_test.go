package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otpdomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func otpSQLFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) (statusFixture, *otppostgres.Repository, otpdomain.Challenge) {
	t.Helper()
	f := newStatusFixture(t, db, ctx, "otp-"+name)
	if _, err := db.Exec(ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	token := tokengenerate.New()
	c := otpdomain.Challenge{Digest: token.Hash("binding-" + name), Verifier: token.Hash("code-" + name), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(5 * time.Minute)}
	return f, otppostgres.New(db), c
}

func checkEmailOTP(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("consume-once-session", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "normal")
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		user, err := repo.Consume(ctx, c.Digest, c.Verifier)
		if err != nil || user.ID != f.user || user.AuthVersion != 1 {
			t.Fatal(user, err)
		}
		sessions := sessionservice.New(clock.UTCClock{}, f.sessions, tokengenerate.New(), sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour})
		issued, err := sessions.CreateSessionAtVersion(ctx, user.ID, "otp", "192.0.2.1", int64(user.AuthVersion))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.sessions.FindSession(ctx, tokengenerate.New().Hash(issued.RawToken)); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("replay", err)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_outbox WHERE digest=$1`, c.Digest).Scan(&count); err != nil || count != 0 {
			t.Fatal("outbox not consumed", count, err)
		}
		var verified *time.Time
		if err := db.QueryRow(ctx, `SELECT password_verified_at FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(issued.RawToken)).Scan(&verified); err != nil || verified != nil {
			t.Fatal("OTP incorrectly gave password fresh auth", err)
		}
	})
	t.Run("five-attempts", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "attempts")
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				if _, err := repo.Consume(ctx, c.Digest, tokengenerate.New().Hash("wrong-code")); !errors.Is(err, otpdomain.ErrInvalidCode) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		var attempts int
		if err := db.QueryRow(ctx, `SELECT attempts FROM auth.email_login_challenges WHERE digest=$1`, c.Digest).Scan(&attempts); err != nil || attempts != otpdomain.MaxAttempts {
			t.Fatal("wrong guesses rolled back or exceeded budget", attempts, err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("exhausted code accepted", err)
		}
	})
	t.Run("parallel-consume", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "parallel")
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var successes atomic.Int64
		for range 16 {
			wg.Go(func() {
				_, err := repo.Consume(ctx, c.Digest, c.Verifier)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, otpdomain.ErrInvalidCode) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("not single use", successes.Load())
		}
	})
	t.Run("replace", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "replace")
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		newer := c
		newer.Digest = tokengenerate.New().Hash("new-binding")
		if err := repo.Issue(ctx, f.email, newer); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
			t.Fatal("old request accepted", err)
		}
		if _, err := repo.Consume(ctx, newer.Digest, newer.Verifier); err != nil {
			t.Fatal(err)
		}
	})
	for _, action := range []string{"unverified", "blocked", "deleted", "pending", "version", "expiry", "changed-email"} {
		t.Run(action, func(t *testing.T) {
			f, repo, c := otpSQLFixture(t, db, ctx, action)
			if err := repo.Issue(ctx, f.email, c); err != nil {
				t.Fatal(err)
			}
			sql := map[string]string{
				"unverified":    `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
				"blocked":       `UPDATE auth.users SET status='blocked' WHERE id=$1`,
				"deleted":       `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`,
				"pending":       `UPDATE auth.users SET status='pending' WHERE id=$1`,
				"version":       `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
				"expiry":        `UPDATE auth.email_login_challenges SET created_at=clock_timestamp()-interval '10 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`,
				"changed-email": `DELETE FROM auth.password_credentials WHERE user_id=$1`,
			}[action]
			if _, err := db.Exec(ctx, sql, f.user); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Consume(ctx, c.Digest, c.Verifier); !errors.Is(err, otpdomain.ErrInvalidCode) {
				t.Fatal(action, err)
			}
			if action != "expiry" {
				var before, after int
				if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_challenges WHERE user_id=$1`, f.user).Scan(&before); err != nil {
					t.Fatal(err)
				}
				other := c
				other.Digest = tokengenerate.New().Hash("ineligible-" + action)
				if err := repo.Issue(ctx, f.email, other); err != nil {
					t.Fatal("generic request failed", err)
				}
				if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_challenges WHERE user_id=$1`, f.user).Scan(&after); err != nil || before != after {
					t.Fatal("ineligible request inserted", err)
				}
			}
		})
	}
	t.Run("unknown-no-registration", func(t *testing.T) {
		_, repo, c := otpSQLFixture(t, db, ctx, "unknown")
		var before, after int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := repo.Issue(ctx, "nonexistent-otp@example.test", c); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&after); err != nil || after != before {
			t.Fatal("implicit registration", err)
		}
	})
	t.Run("delivery-leases", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "delivery")
		// Make the isolated job earliest; other subtests deliberately keep invalidated data.
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_login_outbox SET available_at=clock_timestamp()-interval '1 hour' WHERE digest=$1`, c.Digest); err != nil {
			t.Fatal(err)
		}
		first, err := repo.ClaimDelivery(ctx)
		if err != nil || first == nil || first.Attempts != 1 {
			t.Fatal(first, err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_login_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
			t.Fatal(err)
		}
		second, err := repo.ClaimDelivery(ctx)
		if err != nil || second == nil || second.ID != first.ID || second.Lease == first.Lease || second.Attempts != 2 {
			t.Fatal(second, err)
		}
		if err := repo.FinishDelivery(ctx, *first, true); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_outbox WHERE id=$1`, second.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("stale lease deleted active job", err)
		}
		if err := repo.FinishDelivery(ctx, *second, true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "rollback")
		if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_email_login_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$;
   CREATE TRIGGER reject_email_login_audit BEFORE INSERT ON auth.email_login_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_email_login_audit()`); err != nil {
			t.Fatal(err)
		}
		if err := repo.Issue(ctx, f.email, c); err == nil {
			t.Fatal("issued without audit")
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_challenges WHERE digest=$1`, c.Digest).Scan(&count); err != nil || count != 0 {
			t.Fatal("issue rollback", err)
		}
		if _, err := db.Exec(ctx, `DROP TRIGGER reject_email_login_audit ON auth.email_login_audit`); err != nil {
			t.Fatal(err)
		}
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `CREATE TRIGGER reject_email_login_audit BEFORE INSERT ON auth.email_login_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_email_login_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); err == nil {
			t.Fatal("consumed without audit")
		}
		if _, err := db.Exec(ctx, `DROP TRIGGER reject_email_login_audit ON auth.email_login_audit; DROP FUNCTION auth.reject_email_login_audit()`); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Consume(ctx, c.Digest, c.Verifier); err != nil {
			t.Fatal("consume not rolled back", err)
		}
	})
	t.Run("retention", func(t *testing.T) {
		f, repo, c := otpSQLFixture(t, db, ctx, "retention")
		if err := repo.Issue(ctx, f.email, c); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_login_challenges SET created_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()-interval '1 minute' WHERE user_id=$1;
  `, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := f.accounts.PurgeRetention(ctx, accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100}); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_login_outbox WHERE digest=$1`, c.Digest).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired payload retained", err)
		}
	})
}
