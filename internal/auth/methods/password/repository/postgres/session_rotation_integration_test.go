package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkSessionRotation(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	owner, err := New(db).CreateUser(ctx, "rotation@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	ledger := sessionpostgres.New(db)
	tokens := tokengenerate.New()
	old := tokens.Hash("session-rotation-old")
	p := sessionservice.CreateSessionParams{UserID: owner, AuthVersion: 1, TokenHash: old, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour)}
	if err := ledger.CreateSession(ctx, p); err != nil {
		t.Fatal(err)
	}
	before, err := ledger.FindSession(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	winners := make(chan string, 16)
	for i := range 16 {
		wg.Go(func() {
			hash := tokens.Hash(fmt.Sprintf("session-rotation-winner-%d", i))
			expiry, err := ledger.RotateSession(ctx, owner, old, hash)
			if err == nil {
				if !expiry.Equal(before.ExpiresAt) {
					t.Error("rotation extended expiry")
				}
				winners <- hash
			} else if !errors.Is(err, sessiondomain.ErrSessionNotFound) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(winners)
	if len(winners) != 1 {
		t.Fatalf("rotation winners: %d", len(winners))
	}
	winner := <-winners
	if _, err := ledger.FindSession(ctx, old); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("old token accepted", err)
	}
	after, err := ledger.FindSession(ctx, winner)
	if err != nil || before.ID != after.ID || !before.CreatedAt.Equal(after.CreatedAt) || !before.AbsoluteExpiresAt.Equal(after.AbsoluteExpiresAt) || !before.ExpiresAt.Equal(after.ExpiresAt) {
		t.Fatal("rotation changed session context/deadlines", err)
	}
	if _, err := ledger.RotateSession(ctx, "00000000-0000-4000-8000-000000000000", winner, old); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("foreign user authorized", err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RotateSession(ctx, owner, winner, old); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
		t.Fatal("revoked version resurrected", err)
	}
	for i, tc := range []struct{ name, invalidate string }{
		{"idle expired", `UPDATE auth.sessions SET expires_at=clock_timestamp() WHERE user_id=$1`},
		{"absolute expired", `UPDATE auth.sessions SET expires_at=clock_timestamp(),absolute_expires_at=clock_timestamp() WHERE user_id=$1`},
		{"session revoked", `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1`},
		{"blocked", `UPDATE auth.users SET status='blocked' WHERE id=$1`},
		{"deleted", `UPDATE auth.users SET status='blocked',deleted_at=clock_timestamp() WHERE id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, err := New(db).CreateUser(ctx, fmt.Sprintf("rotation-guard-%d@example.com", i), "hash")
			if err != nil {
				t.Fatal(err)
			}
			p.UserID, p.TokenHash = user, tokens.Hash(fmt.Sprintf("session-rotation-guard-%d", i))
			if err := ledger.CreateSession(ctx, p); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, tc.invalidate, user); err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.RotateSession(ctx, user, p.TokenHash, old); !errors.Is(err, sessiondomain.ErrSessionNotFound) {
				t.Fatal("invalid session rotated", err)
			}
			var stored string
			if err := db.QueryRow(ctx, `SELECT token_hash FROM auth.sessions WHERE user_id=$1`, user).Scan(&stored); err != nil || stored != p.TokenHash {
				t.Fatal("rejected rotation mutated verifier", err)
			}
		})
	}
}
