package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkRefreshFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("spent replay still revokes after current grants disappear", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		if _, err := svc.Refresh(ctx, input); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, binding.Actor.UserID)
		if result, err := svc.Refresh(ctx, input); result != nil || !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("replay stopped at scope guard", err)
		}
		var revoked bool
		if err := db.QueryRow(ctx, `SELECT s.revoked_at IS NOT NULL AND f.revoked_at IS NOT NULL FROM auth.sessions s JOIN auth.refresh_families f ON f.session_id=s.id WHERE s.id=$1`, binding.SessionID).Scan(&revoked); err != nil || !revoked {
			t.Fatal("replay revoke rolled back", err)
		}
	})
	t.Run("signing rollback", func(t *testing.T) {
		_, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		svc := refreshUseCaseService(t, db, failingRefreshSigner{})
		var before, after time.Time
		if err := db.QueryRow(ctx, `SELECT expires_at FROM auth.sessions WHERE id=$1`, binding.SessionID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if result, err := svc.Refresh(ctx, input); result != nil || !errors.Is(err, authjwt.ErrBusy) {
			t.Fatal("sign failure leaked result", err)
		}
		assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
		if err := db.QueryRow(ctx, `SELECT expires_at FROM auth.sessions WHERE id=$1`, binding.SessionID).Scan(&after); err != nil || !before.Equal(after) {
			t.Fatal("renew survived rollback", err)
		}
	})
	t.Run("issuance commit failure hides credentials", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_refresh_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
			CREATE CONSTRAINT TRIGGER reject_refresh_test_commit AFTER INSERT ON auth.token_issuance_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_refresh_test_commit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_refresh_test_commit ON auth.token_issuance_audit; DROP FUNCTION auth.reject_refresh_test_commit()`)
		})
		if result, err := svc.Refresh(ctx, input); result != nil || err == nil {
			t.Fatal("credentials returned before commit")
		}
		assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
	})
	t.Run("replay commit failure is not successful denial", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		if _, err := svc.Refresh(ctx, input); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_refresh_reuse_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event='reuse_detected' THEN RAISE EXCEPTION 'synthetic reuse commit failure'; END IF; RETURN NEW; END $$;
			CREATE CONSTRAINT TRIGGER reject_refresh_reuse_commit AFTER INSERT ON auth.refresh_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_refresh_reuse_commit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_refresh_reuse_commit ON auth.refresh_audit; DROP FUNCTION auth.reject_refresh_reuse_commit()`)
		})
		if result, err := svc.Refresh(ctx, input); result != nil || err == nil || errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("failed revoke claimed as committed", err)
		}
		var revoked bool
		if err := db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.refresh_families WHERE session_id=$1`, binding.SessionID).Scan(&revoked); err != nil || revoked {
			t.Fatal("failed commit mutated family", err)
		}
	})
	t.Run("admin refresh is not activity", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx, true)
		accessExec(t, db, ctx, `UPDATE auth.sessions SET expires_at=clock_timestamp()+interval '40 seconds' WHERE id=$1`, binding.SessionID)
		var before, after time.Time
		if err := db.QueryRow(ctx, `SELECT expires_at FROM auth.sessions WHERE id=$1`, binding.SessionID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		result, err := svc.Refresh(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `SELECT expires_at FROM auth.sessions WHERE id=$1`, binding.SessionID).Scan(&after); err != nil || !before.Equal(after) || result.ExpiresAt.After(before) {
			t.Fatal("background refresh extended admin idle", err)
		}
	})
	t.Run("current password verification and disabled primary", func(t *testing.T) {
		svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
		var policy string
		var enabled bool
		if err := db.QueryRow(ctx, `SELECT password_email_verification,password_enabled FROM auth.auth_settings WHERE singleton`).Scan(&policy, &enabled); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_email_verification=$1,password_enabled=$2 WHERE singleton`, policy, enabled)
		})
		var email string
		if err := db.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES($1,$2) RETURNING id`, binding.Actor.UserID, string(binding.Actor.UserID)+"@example.test").Scan(&email); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,$2,'synthetic hash')`, binding.Actor.UserID, email)
		accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_email_verification='required',password_enabled=false WHERE singleton`)
		if result, err := svc.Refresh(ctx, input); result != nil || !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("current policy bypassed", err)
		}
		assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE id=$1`, email)
		if _, err := svc.Refresh(ctx, input); err != nil {
			t.Fatal("disabled primary revoked existing session", err)
		}
	})
	for _, test := range []struct {
		name, query string
		access      bool
		want        error
	}{
		{"pending block", `UPDATE auth.users SET status='blocked' WHERE id=$1`, false, tokendomain.ErrInvalidRefresh},
		{"pending scope revoke", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, true, tokendomain.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, binding, input, _ := refreshUseCaseFixture(t, db, ctx)
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if test.access {
				if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, test.query, binding.Actor.UserID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				result, err := svc.Refresh(ctx, input)
				if result != nil {
					done <- errors.New("stale refresh issued")
					return
				}
				done <- err
			}()
			waitJWTSQLLock(t, db, ctx)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, test.want) {
				t.Fatal("stale authority", err)
			}
			assertRefreshUnconsumed(t, db, ctx, binding.SessionID)
		})
	}
}
