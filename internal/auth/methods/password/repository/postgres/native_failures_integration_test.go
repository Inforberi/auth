package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkNativeIssuanceFailures(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	for _, test := range []struct {
		name  string
		shift time.Duration
	}{
		{"stale primary", -2 * time.Minute}, {"future primary", time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, input, _ := nativeIssuanceFixture(t, db, ctx)
			input.Proof.VerifiedAt = time.Now().Add(test.shift)
			if result, err := svc.IssueNative(ctx, input); result != nil || !errors.Is(err, mfadomain.ErrProofRequired) {
				t.Fatal("unbounded proof age", err)
			}
			assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		})
	}
	t.Run("sign failure rolls back ledger family audit", func(t *testing.T) {
		_, input, _ := nativeIssuanceFixture(t, db, ctx)
		svc := nativeTokenService(t, db, failingRefreshSigner{})
		if result, err := svc.IssueNative(ctx, input); result != nil || !errors.Is(err, authjwt.ErrBusy) {
			t.Fatal("failed signing exposed result", err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
	})
	t.Run("commit failure rolls back first credentials", func(t *testing.T) {
		svc, input, _ := nativeIssuanceFixture(t, db, ctx)
		accessExec(t, db, ctx, `CREATE FUNCTION auth.reject_native_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$;
			CREATE CONSTRAINT TRIGGER reject_native_commit AFTER INSERT ON auth.token_issuance_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION auth.reject_native_commit()`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `DROP TRIGGER reject_native_commit ON auth.token_issuance_audit; DROP FUNCTION auth.reject_native_commit()`)
		})
		if result, err := svc.IssueNative(ctx, input); result != nil || err == nil {
			t.Fatal("credentials returned before commit")
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
	})
	t.Run("current primary policy", func(t *testing.T) {
		svc, input, _ := nativeIssuanceFixture(t, db, ctx)
		var previous string
		var enabled bool
		if err := db.QueryRow(ctx, `SELECT password_email_verification,password_enabled FROM auth.auth_settings WHERE singleton`).Scan(&previous, &enabled); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_email_verification=$1,password_enabled=$2 WHERE singleton`, previous, enabled)
		})
		accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=false WHERE singleton`)
		if result, err := svc.IssueNative(ctx, input); result != nil || !errors.Is(err, settingsdomain.ErrMethodDisabled) {
			t.Fatal("disabled primary issued", err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		accessExec(t, db, ctx, `UPDATE auth.auth_settings SET password_enabled=true,password_email_verification='required' WHERE singleton`)
		if result, err := svc.IssueNative(ctx, input); result != nil || !errors.Is(err, accountdomain.ErrEmailUnverified) {
			t.Fatal("required verification bypassed", err)
		}
		assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
	})
	for _, test := range []struct {
		name, query string
		access      bool
		want        error
	}{
		{"pending block", `UPDATE auth.users SET status='blocked' WHERE id=$1`, false, mfadomain.ErrProofRequired},
		{"pending grant revoke", `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, true, tokendomain.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, input, _ := nativeIssuanceFixture(t, db, ctx)
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
			if _, err := tx.Exec(ctx, test.query, input.Proof.UserID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				result, err := svc.IssueNative(ctx, input)
				if result != nil {
					done <- errors.New("issued behind pending revoke")
					return
				}
				done <- err
			}()
			waitJWTSQLLock(t, db, ctx)
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, test.want) {
				t.Fatal("stale native authorization", err)
			}
			assertNativeRows(t, db, ctx, string(input.Proof.UserID), 0)
		})
	}
}
