package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkAdministratorRecovery(t *testing.T, db *pgxpool.Pool, ctx context.Context, role string) {
	t.Run("standard-reset-preserves-role", func(t *testing.T) {
		f := newMFALoginFixture(t, db, ctx, "admin-reset").statusFixture
		assignAdministrator(t, db, ctx, role, f.user)
		accessExec(t, db, ctx, `UPDATE auth.user_emails SET verified_at=clock_timestamp() WHERE user_id=$1`, f.user)
		challenge := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("admin-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.passwords.IssueReset(ctx, f.email, challenge); err != nil {
			t.Fatal(err)
		}
		if err := f.passwords.ConsumeReset(ctx, challenge.Digest, "replacement"); err != nil {
			t.Fatal(err)
		}
		assertAdministratorRole(t, db, ctx, f.user, role, "active")
		var factors, codes int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1),(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1)`, f.user).Scan(&factors, &codes); err != nil || factors != 1 || codes != 10 {
			t.Fatal("standard reset changed MFA", err)
		}
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 3); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("reset lost administrator protection", err)
		}
	})
	t.Run("standard-reset-does-not-unblock", func(t *testing.T) {
		f := newStatusFixture(t, db, ctx, "admin-blocked-reset")
		assignAdministrator(t, db, ctx, role, f.user)
		challenge := passworddomain.ResetChallenge{Digest: tokengenerate.New().Hash("admin-blocked-reset"), Payload: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}
		if err := f.passwords.IssueReset(ctx, f.email, challenge); err != nil {
			t.Fatal(err)
		}
		accessExec(t, db, ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.user)
		if err := f.passwords.ConsumeReset(ctx, challenge.Digest, "replacement"); !errors.Is(err, passworddomain.ErrInvalidReset) {
			t.Fatal("blocked reset accepted", err)
		}
		accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`, f.user)
		assertAdministratorRole(t, db, ctx, f.user, role, "blocked")
	})
	t.Run("security-containment-preserves-recovery", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "last-admin-protection")
		assignAdministrator(t, db, ctx, role, f.user)
		if err := f.request(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ConfirmEmailChange(ctx, f.intent.ConfirmDigest); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.ReportEmailChange(ctx, f.intent.ReportDigest); err != nil {
			t.Fatal("last-admin guard disabled security containment", err)
		}
		assertAdministratorRole(t, db, ctx, f.user, role, "blocked")
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 3); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("administrative no-op cancelled last recovery", err)
		}
		if _, err := deleteFixture(ctx, f.statusFixture, 3); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("deleted last recoverable administrator", err)
		}
		if hash, err := f.accounts.ProtectedRecoveryHash(ctx, f.intent.RecoveryDigest); err != nil || hash != "old-hash" {
			t.Fatal("failed removal cancelled recovery", hash, err)
		}
		if err := f.accounts.RecoverProtectedAccount(ctx, f.intent.RecoveryDigest, "old-hash", "replacement"); err != nil {
			t.Fatal(err)
		}
		assertAdministratorRole(t, db, ctx, f.user, role, "active")
		if _, err := f.change(ctx, accountdomain.StatusBlocked, 4); !errors.Is(err, accountdomain.ErrLastAdministrator) {
			t.Fatal("recovered administrator not protected", err)
		}
	})
}

func assertAdministratorRole(t *testing.T, db *pgxpool.Pool, ctx context.Context, user accountdomain.UserID, role, status string) {
	t.Helper()
	var intact bool
	if err := db.QueryRow(ctx, `SELECT status=$3 AND deleted_at IS NULL
		AND EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2)
		AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)
		FROM auth.users WHERE id=$1`, user, role, status).Scan(&intact); err != nil || !intact {
		t.Fatal("recovery changed role/status or created session", intact, err)
	}
}
