package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func protectedFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) changeFixture {
	t.Helper()
	f := newChangeFixture(t, db, ctx, "protected-"+name)
	if err := f.request(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
		t.Fatal(err)
	}
	if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
		t.Fatal(err)
	}
	return f
}

func checkProtectedRecovery(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("one-time-and-purpose", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "protected-before-report")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("unissued proof valid", err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal(err)
		}
		for _, digest := range []string{f.intent.ConfirmDigest, f.intent.ReportDigest} {
			if err := f.accounts.RecoverProtectedAccount(ctx, digest, "old-hash", "replacement"); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal("purpose confused", err)
			}
		}
		var queued int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='recovery'`, f.user).Scan(&queued); err != nil || queued != 1 {
			t.Fatal("missing recovery delivery", queued, err)
		}
		hash, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest)
		if err != nil || hash != "old-hash" {
			t.Fatal(hash, err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, hash, "replacement"); err != nil {
			t.Fatal(err)
		}
		credential, err := f.passwords.FindByEmail(ctx, f.email)
		if err != nil || credential.PasswordHash != "replacement" || credential.AuthVersion != 4 {
			t.Fatal("unsafe credential restoration", credential, err)
		}
		if _, err := f.passwords.FindByEmail(ctx, f.newEmail); !errors.Is(err, passworddomain.ErrUserNotFound) {
			t.Fatal("attacker address remains login", err)
		}
		var trusted bool
		if err := db.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM auth.user_emails WHERE email=$1`, f.newEmail).Scan(&trusted); err != nil || trusted {
			t.Fatal("attacker contact remains trusted", trusted, err)
		}
		if _, err := f.sessions.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("session resurrected", err)
		}
		for _, fn := range []func() error{
			func() error { return f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, hash, "another") },
			func() error { return f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest) },
			func() error { return f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest) },
		} {
			if err := fn(); err == nil {
				t.Fatal("old authority survived recovery")
			}
		}
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1`, f.user).Scan(&queued); err != nil || queued != 0 {
			t.Fatal("stale jobs survived", queued, err)
		}
	})
	for name, sql := range map[string]string{
		"expiry":                `UPDATE auth.email_changes SET recovery_expires_at=clock_timestamp()-interval '1 minute' WHERE user_id=$1`,
		"version":               `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		"deleted":               `UPDATE auth.users SET deleted_at=clock_timestamp() WHERE id=$1`,
		"lost old verification": `UPDATE auth.user_emails SET verified_at=NULL WHERE user_id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			f := protectedFixture(t, db, ctx, name)
			if _, err := db.Exec(ctx, sql, f.user); err != nil {
				t.Fatal(err)
			}
			if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal("invalid proof snapshot", err)
			}
			if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal("invalid recovery committed", err)
			}
		})
	}
	t.Run("stale-hash", func(t *testing.T) {
		f := protectedFixture(t, db, ctx, "stale-hash")
		if _, err := db.Exec(ctx, `UPDATE auth.password_credentials SET password_hash='changed' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("stale hash accepted", err)
		}
	})
	t.Run("administrative-block", func(t *testing.T) {
		f := protectedFixture(t, db, ctx, "admin")
		if v, err := f.change(ctx, accountdomain.StatusBlocked, 3); err != nil || v != 3 {
			t.Fatal(v, err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("administrative block bypassed", err)
		}
		assertInactiveAccount(t, ctx, f.statusFixture)
	})
	t.Run("near-protection-expiry", func(t *testing.T) {
		f := protectedFixture(t, db, ctx, "near-expiry")
		if _, err := db.Exec(ctx, `UPDATE auth.email_changes SET created_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour',protect_until=clock_timestamp()-interval '1 minute' WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if _, err := f.accounts.PurgeRetention(ctx, retentionPolicy()); err != nil {
			t.Fatal(err)
		}
		if hash, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); err != nil || hash != "old-hash" {
			t.Fatal("worker discarded unexpired recovery", hash, err)
		}
	})
	t.Run("legacy-intent", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "legacy-protection")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE auth.email_changes SET recovery_digest=NULL,recovery_payload=NULL,recovery_ttl_seconds=NULL WHERE user_id=$1`, f.user); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal("upgrade disabled protection", err)
		}
		assertInactiveAccount(t, ctx, f.statusFixture)
		if _, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
			t.Fatal("legacy intent granted recovery", err)
		}
	})
	t.Run("concurrent-consume", func(t *testing.T) {
		f := protectedFixture(t, db, ctx, "race")
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() {
				errs <- f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement")
			})
		}
		wg.Wait()
		close(errs)
		success := 0
		for err := range errs {
			if err == nil {
				success++
			} else if !errors.Is(err, accountdomain.ErrInvalidAccountRecovery) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatal("multiple recovery commits", success)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f := protectedFixture(t, db, ctx, "rollback")
		if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='recovered' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON auth.email_change_audit FOR EACH ROW EXECUTE FUNCTION auth.reject_recovery_audit()`); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); err == nil {
			t.Fatal("committed without audit")
		}
		assertInactiveAccount(t, ctx, f.statusFixture)
		if hash, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); err != nil || hash != "old-hash" {
			t.Fatal("rollback consumed proof/hash", hash, err)
		}
		if _, err := db.Exec(ctx, `DROP TRIGGER reject_recovery_audit ON auth.email_change_audit; DROP FUNCTION auth.reject_recovery_audit()`); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("recovery-outbox-rollback", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "protected-outbox-rollback")
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `CREATE FUNCTION auth.reject_recovery_mail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='recovery' THEN RAISE EXCEPTION 'outbox unavailable'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_recovery_mail BEFORE INSERT ON auth.email_change_outbox FOR EACH ROW EXECUTE FUNCTION auth.reject_recovery_mail()`); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err == nil {
			t.Fatal("blocked without recovery intent")
		}
		assertChangeLogin(t, ctx, f, f.newEmail, 2)
		if _, err := db.Exec(ctx, `DROP TRIGGER reject_recovery_mail ON auth.email_change_outbox; DROP FUNCTION auth.reject_recovery_mail()`); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal(fmt.Errorf("rollback consumed report: %w", err))
		}
	})
}
