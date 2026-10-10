package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func retentionPolicy() accountservice.RetentionConfig {
	return accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180}
}

func ageDeletion(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID) {
	t.Helper()
	if _, err := db.Exec(ctx, `UPDATE auth.users SET created_at=clock_timestamp()-interval '40 days',
		deleted_at=clock_timestamp()-interval '31 days' WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
}

func contactCount(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.user_emails WHERE user_id=$1`, user).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func checkRetention(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("reservation-release-and-new-proof", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-reuse")
		oldProof := accountdomain.Verification{Digest: tokengenerate.New().Hash("retention-old-proof"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.accounts.Issue(ctx, f.email, oldProof, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := deleteFixture(ctx, f, 1); err != nil {
			t.Fatal(err)
		}
		worker := accountservice.NewRetention(f.accounts, retentionPolicy())
		if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 1 {
			t.Fatal("early release", err)
		}
		ageDeletion(t, db, ctx, f.user)
		if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 0 {
			t.Fatal("contact not released", err)
		}
		var released bool
		if err := db.QueryRow(ctx, `SELECT email_released_at IS NOT NULL FROM auth.users WHERE id=$1`, f.user).Scan(&released); err != nil || !released {
			t.Fatal("released owner remains in work queue", released, err)
		}
		newUser, err := f.passwords.CreateUser(ctx, f.email, "new-password")
		if err != nil || newUser == f.user {
			t.Fatal("old UUID reused", newUser, err)
		}
		if err := f.accounts.RequireVerified(ctx, newUser); !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("verification inherited", err)
		}
		if err := f.accounts.Confirm(ctx, oldProof.Digest); !errors.Is(err, accountdomain.ErrInvalidVerification) {
			t.Fatal("old proof accepted", err)
		}
		proof := accountdomain.Verification{Digest: tokengenerate.New().Hash("retention-new-proof"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.accounts.Issue(ctx, f.email, proof, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.Confirm(ctx, proof.Digest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.RequireVerified(ctx, newUser); err != nil {
			t.Fatal(err)
		}
		if _, err := f.change(ctx, accountdomain.StatusActive, 2); !errors.Is(err, accountdomain.ErrAccountDeleted) {
			t.Fatal("tombstone restored", err)
		}
		if version, err := deleteFixture(ctx, f, 2); err != nil || version != 2 {
			t.Fatal("retry after cleanup", version, err)
		}
	})
	t.Run("blocked-address-not-released", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-blocked")
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := deleteFixture(ctx, f, 2); err != nil {
			t.Fatal(err)
		}
		ageDeletion(t, db, ctx, f.user)
		if _, err := accountservice.NewRetention(f.accounts, retentionPolicy()).Purge(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.passwords.CreateUser(ctx, f.email, "new-password"); !errors.Is(err, passworddomain.ErrEmailAlreadyExists) {
			t.Fatal("deletion bypassed block", err)
		}
	})
	t.Run("session-and-audit-clocks", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-clocks")
		for _, kind := range []string{"revoked", "expired", "recent", "active"} {
			var revoked *time.Time
			created := time.Now().Add(-40 * 24 * time.Hour)
			expires := time.Now().Add(time.Hour)
			if kind == "revoked" {
				v := time.Now().Add(-31 * 24 * time.Hour)
				revoked = &v
			}
			if kind == "expired" || kind == "recent" {
				expires = time.Now().Add(-32 * 24 * time.Hour)
			}
			if kind == "recent" {
				// Expiry predates revocation; count from the earlier completion.
				v := time.Now().Add(-time.Hour)
				revoked = &v
			}
			if _, err := db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,revoked_at,user_agent,ip_address)
				VALUES ($1,$2,1,$3,$4,$5,$6,'','')`, tokengenerate.New().Hash("retention-"+kind), f.user, created, expires, expires.Add(time.Hour), revoked); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event,created_at) VALUES
			($1,'password_changed',clock_timestamp()-interval '181 days'),($1,'password_changed',clock_timestamp()-interval '179 days')`, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := accountservice.NewRetention(f.accounts, retentionPolicy()).Purge(ctx); err != nil {
			t.Fatal(err)
		}
		var sessions, audit int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.sessions WHERE user_id=$1),
			(SELECT count(*) FROM auth.password_audit WHERE user_id=$1)`, f.user).Scan(&sessions, &audit); err != nil || sessions != 2 || audit != 1 {
			t.Fatal("incorrect retention", sessions, audit, err)
		}
	})
	t.Run("bounded-and-skip-locked", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-batch")
		if _, err := deleteFixture(ctx, f, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email)
			SELECT $1,'retention-extra-'||n||'@example.com' FROM generate_series(1,100) n`, f.user); err != nil {
			t.Fatal(err)
		}
		ageDeletion(t, db, ctx, f.user)
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT id FROM auth.users WHERE id=$1 FOR UPDATE`, f.user); err != nil {
			t.Fatal(err)
		}
		worker := accountservice.NewRetention(f.accounts, retentionPolicy())
		if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 101 {
			t.Fatal("locked owner not skipped", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := worker.Purge(ctx); err != nil || contactCount(t, db, ctx, f.user) != 1 {
			t.Fatal("unbounded batch", err)
		}
		left, right := protectionPair(func() error { _, err := worker.Purge(ctx); return err }, func() error { _, err := worker.Purge(ctx); return err })
		if left != nil || right != nil || contactCount(t, db, ctx, f.user) != 0 {
			t.Fatal("concurrent worker takeover", left, right)
		}
	})
	t.Run("all-audits-and-deletion-retry", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-all-audits")
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := f.change(ctx, accountdomain.StatusActive, 2); err != nil {
			t.Fatal(err)
		}
		if _, err := deleteFixture(ctx, f, 3); err != nil {
			t.Fatal(err)
		}
		for _, query := range []string{
			`INSERT INTO auth.email_verification_audit(user_id,event) VALUES ($1,'email_verified')`,
			`INSERT INTO auth.password_audit(user_id,event) VALUES ($1,'password_changed')`,
			`INSERT INTO auth.email_change_audit(user_id,change_id,event) VALUES ($1,gen_random_uuid(),'requested')`,
		} {
			if _, err := db.Exec(ctx, query, f.user); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"email_verification_audit", "password_audit", "account_status_audit", "account_deletion_audit", "email_change_audit"} {
			if _, err := db.Exec(ctx, `UPDATE auth.`+table+` SET created_at=clock_timestamp()-interval '181 days' WHERE user_id=$1`, f.user); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := accountservice.NewRetention(f.accounts, retentionPolicy()).Purge(ctx); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"email_verification_audit", "password_audit", "account_status_audit", "account_deletion_audit", "email_change_audit"} {
			var count int
			if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.`+table+` WHERE user_id=$1`, f.user).Scan(&count); err != nil || count != 0 {
				t.Fatal("audit retained", table, count, err)
			}
		}
		if version, err := deleteFixture(ctx, f, 4); err != nil || version != 4 {
			t.Fatal("retry depends on purged audit", version, err)
		}
	})
	t.Run("purge-registration-race", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-race")
		if _, err := deleteFixture(ctx, f, 1); err != nil {
			t.Fatal(err)
		}
		ageDeletion(t, db, ctx, f.user)
		worker := accountservice.NewRetention(f.accounts, retentionPolicy())
		var newUser accountdomain.UserID
		purgeErr, registerErr := protectionPair(func() error { _, err := worker.Purge(ctx); return err }, func() error {
			var err error
			newUser, err = f.passwords.CreateUser(ctx, f.email, "replacement")
			return err
		})
		if purgeErr != nil || (registerErr != nil && !errors.Is(registerErr, passworddomain.ErrEmailAlreadyExists)) {
			t.Fatal(purgeErr, registerErr)
		}
		if registerErr != nil {
			var err error
			newUser, err = f.passwords.CreateUser(ctx, f.email, "replacement")
			if err != nil {
				t.Fatal(err)
			}
		}
		if newUser == f.user {
			t.Fatal("old UUID reused")
		}
		if err := f.accounts.RequireVerified(ctx, newUser); !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("ownership inherited", err)
		}
	})
	t.Run("audit-failure-rolls-back-purge", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "retention-rollback")
		if _, err := deleteFixture(ctx, f, 1); err != nil {
			t.Fatal(err)
		}
		ageDeletion(t, db, ctx, f.user)
		if _, err := db.Exec(ctx, `UPDATE auth.account_deletion_audit SET created_at=clock_timestamp()-interval '181 days' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `CREATE FUNCTION auth.fail_retention() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'test retention failure'; END $$;
			CREATE TRIGGER fail_retention BEFORE DELETE ON auth.account_deletion_audit FOR EACH ROW EXECUTE FUNCTION auth.fail_retention()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(ctx, `DROP TRIGGER fail_retention ON auth.account_deletion_audit; DROP FUNCTION auth.fail_retention()`); err != nil {
				t.Error(err)
			}
		}()
		if count, err := accountservice.NewRetention(f.accounts, retentionPolicy()).Purge(ctx); err == nil || count != 0 || contactCount(t, db, ctx, f.user) != 1 {
			t.Fatal("partial purge committed", count, err)
		}
	})
}
