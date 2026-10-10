package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func checkConcurrentRefresh(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	f := newStatusFixture(t, db, ctx, "refresh-concurrent")
	snapshot, err := f.sessions.FindSession(ctx, f.params.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	oldExpiry := snapshot.ExpiresAt
	wanted := snapshot.ExpiresAt.Add(30 * time.Minute)
	var writes atomic.Int64
	var burst sync.WaitGroup
	for range 32 {
		burst.Go(func() {
			candidate := *snapshot
			candidate.ExpiresAt = wanted
			extended, err := f.sessions.RefreshSession(ctx, f.params.TokenHash, &candidate, oldExpiry)
			if err != nil || !candidate.ExpiresAt.Equal(wanted) {
				t.Error(candidate.ExpiresAt, err)
			}
			if extended {
				writes.Add(1)
			}
		})
	}
	burst.Wait()
	if writes.Load() != 1 {
		t.Fatal("duplicate refresh writes", writes.Load())
	}
	candidate := *snapshot
	candidate.ExpiresAt = oldExpiry.Add(time.Minute)
	if extended, err := f.sessions.RefreshSession(ctx, f.params.TokenHash, &candidate, wanted); err != nil || extended || !candidate.ExpiresAt.Equal(wanted) {
		t.Fatal("refresh shortened expiry", candidate.ExpiresAt, err)
	}
}
