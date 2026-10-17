package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func assertNativeFactorUnconsumed(t *testing.T, db *pgxpool.Pool, ctx context.Context, f nativeMFAFixture) {
	t.Helper()
	assertNativeMFARows(t, db, ctx, f, 0)
	var intact bool
	if err := db.QueryRow(ctx, `SELECT c.attempts=0 AND (SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=c.user_id)=10
		AND NOT EXISTS(SELECT 1 FROM auth.mfa_audit WHERE user_id=c.user_id AND event='recovery_used')
		FROM auth.mfa_login_challenges c WHERE c.user_id=$1 AND c.credential_profile='api'`, f.user).Scan(&intact); err != nil || !intact {
		t.Fatal("factor/challenge survived failed transaction incorrectly", err)
	}
}

func checkNativeMFAFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("sign failure restores factor and challenge", func(t *testing.T) {
		f := newNativeMFAFixture(t, db, ctx, "sign-failure")
		failed, err := tokenservice.NewNativeLogin(nativeTokenService(t, db, failingRefreshSigner{}), f.login)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := failed.Complete(ctx, f.input); result != nil || !errors.Is(err, authjwt.ErrBusy) {
			t.Fatal("failed signing exposed credentials", err)
		}
		assertNativeFactorUnconsumed(t, db, ctx, f)
		if _, err := f.coordinator.Complete(ctx, f.input); err != nil {
			t.Fatal("rollback consumed recovery code", err)
		}
	})
	t.Run("commit failure restores factor and challenge", func(t *testing.T) {
		f := newNativeMFAFixture(t, db, ctx, "commit-failure")
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_native_mfa_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
			CREATE CONSTRAINT TRIGGER reject_native_mfa_commit AFTER INSERT ON auth.token_issuance_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_native_mfa_commit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_native_mfa_commit ON auth.token_issuance_audit; DROP FUNCTION auth.reject_native_mfa_commit()`)
		})
		if result, err := f.coordinator.Complete(ctx, f.input); result != nil || err == nil {
			t.Fatal("token leaked before commit")
		}
		assertNativeFactorUnconsumed(t, db, ctx, f)
	})
	for _, test := range []struct {
		name, query string
		access      bool
		want        error
	}{
		{"pending block", `UPDATE auth.users SET status='blocked' WHERE id=$1`, false, mfadomain.ErrInvalidCode},
		{"pending grant revoke", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, true, tokendomain.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNativeMFAFixture(t, db, ctx, test.name)
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
			if _, err := tx.Exec(ctx, test.query, f.user); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				result, err := f.coordinator.Complete(ctx, f.input)
				if result != nil {
					done <- errors.New("issued behind pending mutation")
					return
				}
				done <- err
			}()
			waitJWTSQLLock(t, db, ctx)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, test.want) {
				t.Fatal("stale MFA completion", err)
			}
			assertNativeFactorUnconsumed(t, db, ctx, f)
		})
	}
}
