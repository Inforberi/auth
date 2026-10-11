package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkFreshAuthentication(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	ledger := sessionpostgres.New(db)
	for i, tc := range []struct{ name, query string }{
		{"version", `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`},
		{"password snapshot", `UPDATE auth.password_credentials SET password_hash='different' WHERE user_id=$1`},
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`},
		{"deleted", `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`},
		{"revoked", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`},
		{"expired", `UPDATE auth.sessions SET expires_at=clock_timestamp() WHERE user_id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChangeFixture(t, db, ctx, fmt.Sprintf("fresh-guard-%d", i))
			if _, err := db.Exec(ctx, tc.query, f.user); err != nil {
				t.Fatal(err)
			}
			if proof, err := ledger.ConfirmPassword(ctx, f.user, f.params.TokenHash, f.snapshot.PasswordHash, 1, fmt.Sprintf("%064x", i+5000)); !errors.Is(err, sessiondomain.ErrSessionNotFound) || proof != nil {
				t.Fatal("stale confirmation accepted", proof, err)
			}
		})
	}
	t.Run("email-change-without-second-password", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "fresh")
		request := func() error {
			return f.accounts.RequestEmailChange(ctx, f.snapshot, f.params.TokenHash, f.newEmail, f.intent, false, 5*time.Minute)
		}
		if err := request(); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("missing proof accepted", err)
		}
		old := f.params.TokenHash
		before, err := ledger.FindSession(ctx, old)
		if err != nil {
			t.Fatal(err)
		}
		next := strings.Repeat("b", 64)
		if _, err := ledger.ConfirmPassword(ctx, f.user, old, "wrong-hash", 1, next); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("stale password proof accepted", err)
		}
		proof, err := ledger.ConfirmPassword(ctx, f.user, old, f.snapshot.PasswordHash, 1, next)
		if err != nil {
			t.Fatal(err)
		}
		after, err := ledger.FindSession(ctx, next)
		if err != nil || after.ID != before.ID || !after.CreatedAt.Equal(before.CreatedAt) || !after.ExpiresAt.Equal(before.ExpiresAt) || !after.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt) {
			t.Fatal("reauthentication changed context/deadlines", err)
		}
		other := f.params
		other.TokenHash = tokengenerate.New().Hash("fresh-auth-other-session")
		if err := ledger.CreateSession(ctx, other); err != nil {
			t.Fatal(err)
		}
		if err := f.accounts.RequestEmailChange(ctx, f.snapshot, other.TokenHash, f.newEmail, f.intent, false, 5*time.Minute); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
			t.Fatal("proof leaked to other session", err)
		}
		if _, err := ledger.FindSession(ctx, old); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("old cookie accepted", err)
		}
		f.params.TokenHash = next
		for _, offset := range []string{"NULL", "clock_timestamp()-interval '5 minutes'", "clock_timestamp()+interval '1 minute'"} {
			if _, err := db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=`+offset+` WHERE token_hash=$1`, next); err != nil {
				t.Fatal(err)
			}
			if err := request(); !errors.Is(err, accountdomain.ErrFreshAuthRequired) {
				t.Fatal("stale/future/missing proof accepted", offset, err)
			}
		}
		if _, err := db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=$2 WHERE token_hash=$1`, next, proof.VerifiedAt); err != nil {
			t.Fatal(err)
		}
		rotated := strings.Repeat("c", 64)
		if _, err := ledger.RotateSession(ctx, f.user, next, rotated); err != nil {
			t.Fatal(err)
		}
		var preserved time.Time
		if err := db.QueryRow(ctx, `SELECT password_verified_at FROM auth.sessions WHERE token_hash=$1`, rotated).Scan(&preserved); err != nil || !preserved.Equal(proof.VerifiedAt) {
			t.Fatal("rotation refreshed proof", err)
		}
		f.params.TokenHash = rotated
		if err := request(); err != nil {
			t.Fatal("fresh proof rejected", err)
		}
		var count int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.password_audit WHERE user_id=$1 AND event='password_reauthenticated'`, f.user).Scan(&count); err != nil || count != 1 {
			t.Fatal("confirmation audit", count, err)
		}
	})
	t.Run("one-winner", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "fresh-race")
		var wg sync.WaitGroup
		winners := make(chan string, 16)
		for i := range 16 {
			wg.Go(func() {
				next := fmt.Sprintf("%064x", i+3000)
				if _, err := ledger.ConfirmPassword(ctx, f.user, f.params.TokenHash, f.snapshot.PasswordHash, 1, next); err == nil {
					winners <- next
				} else if !errors.Is(err, sessiondomain.ErrSessionNotFound) {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		close(winners)
		if len(winners) != 1 {
			t.Fatalf("confirmation winners: %d", len(winners))
		}
		if _, err := ledger.FindSession(ctx, f.params.TokenHash); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
			t.Fatal("old token survived", err)
		}
	})
	t.Run("audit-rollback", func(t *testing.T) {
		f := newChangeFixture(t, db, ctx, "fresh-rollback")
		if _, err := db.Exec(ctx, fmt.Sprintf(`ALTER TABLE auth.password_audit ADD CONSTRAINT reject_fresh_test CHECK(user_id<>'%s'::uuid)`, f.user)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.Exec(ctx, `ALTER TABLE auth.password_audit DROP CONSTRAINT reject_fresh_test`); err != nil {
				t.Error(err)
			}
		}()
		if proof, err := ledger.ConfirmPassword(ctx, f.user, f.params.TokenHash, f.snapshot.PasswordHash, 1, strings.Repeat("d", 64)); err == nil || proof != nil {
			t.Fatal("audit failure committed proof", err)
		}
		if _, err := ledger.FindSession(ctx, f.params.TokenHash); err != nil {
			t.Fatal("audit failure rotated token", err)
		}
		var empty bool
		if err := db.QueryRow(ctx, `SELECT password_verified_at IS NULL FROM auth.sessions WHERE token_hash=$1`, f.params.TokenHash).Scan(&empty); err != nil || !empty {
			t.Fatal("audit failure retained proof", err)
		}
	})
}
