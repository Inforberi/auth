package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type fakeSQLPool struct {
	fakePool
	native *pgxpool.Pool
}

func (p *fakeSQLPool) sqlPool() *pgxpool.Pool { return p.native }

func TestPoolLeaseSingleFlightWithoutConnection(t *testing.T) {
	var opens atomic.Int32
	p := &fakeSQLPool{fakePool: fakePool{leases: make(chan struct{}, 1)}, native: &pgxpool.Pool{}}
	opening, proceed := make(chan struct{}), make(chan struct{})
	r := newRegistry(testConfig(), func(ctx context.Context, _ Key) (pool, error) {
		opens.Add(1)
		close(opening)
		select {
		case <-proceed:
			return p, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	cleanupRegistry(t, r)
	results := make(chan error, 8)
	var correct atomic.Int32
	for range 8 {
		go func() {
			results <- r.UsePool(t.Context(), testKey(), func(_ context.Context, db *pgxpool.Pool) error {
				if db == p.native {
					correct.Add(1)
				}
				return nil
			})
		}()
	}
	<-opening
	close(proceed)
	for range 8 {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, 1, opens.Load())
	require.EqualValues(t, 8, correct.Load())
	require.Empty(t, p.leases, "logical leases must not acquire physical connections")
	require.False(t, p.closed.Load())
}

func TestPoolLeaseBoundsAndDrain(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAcquiring = 1
	p := &fakeSQLPool{fakePool: fakePool{leases: make(chan struct{}, 1)}, native: &pgxpool.Pool{}}
	r := newRegistry(cfg, func(context.Context, Key) (pool, error) { return p, nil })
	cleanupRegistry(t, r)
	entered, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- r.UsePool(t.Context(), testKey(), func(context.Context, *pgxpool.Pool) error { close(entered); <-finish; return nil })
	}()
	<-entered
	require.ErrorIs(t, r.UsePool(t.Context(), testKey(), func(context.Context, *pgxpool.Pool) error { return nil }), ErrBusy)
	require.ErrorIs(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }), ErrBusy)
	r.Invalidate(testKey())
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.Error(t, r.Close(canceled))
	require.False(t, p.closed.Load(), "shutdown/invalidation must preserve the callback's pool")
	require.Empty(t, p.leases)
	close(finish)
	require.NoError(t, <-result)
	require.Eventually(t, func() bool { return p.closed.Load() }, time.Second, time.Millisecond)
}

func TestPoolLeaseReleasesOnErrorAndPanic(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAcquiring = 1
	p := &fakeSQLPool{fakePool: fakePool{leases: make(chan struct{}, 1)}, native: &pgxpool.Pool{}}
	r := newRegistry(cfg, func(context.Context, Key) (pool, error) { return p, nil })
	cleanupRegistry(t, r)
	expected := errors.New("fixture callback failed")
	require.ErrorIs(t, r.UsePool(t.Context(), testKey(), func(context.Context, *pgxpool.Pool) error { return expected }), expected)
	require.Panics(t, func() {
		_ = r.UsePool(t.Context(), testKey(), func(context.Context, *pgxpool.Pool) error { panic("fixture panic") })
	})
	require.NoError(t, r.UsePool(t.Context(), testKey(), func(context.Context, *pgxpool.Pool) error { return nil }))
	require.Empty(t, r.acquires)
	require.Empty(t, p.leases)
}
