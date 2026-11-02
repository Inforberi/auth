package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
)

func testKey() Key {
	return Key{Version: 1, Generation: 1, Binding: credentials.Binding{
		RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: "a2000000-0000-4000-8000-000000000001",
		ReservationID: "b2000000-0000-4000-8000-000000000001", StorageTarget: "primary",
		DatabaseOID: 101, OwnerOID: 102, RuntimeOID: 103, SchemaVersion: 1,
	}}
}

func testConfig() Config {
	return Config{
		MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1,
		MaxAcquiring: 8, AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Hour,
	}
}

type fakePool struct {
	closed atomic.Bool
	leases chan struct{}
}

func (p *fakePool) acquire(ctx context.Context) (connection, error) {
	select {
	case p.leases <- struct{}{}:
		return &fakeConnection{pool: p}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *fakePool) Close() { p.closed.Store(true) }

type fakeConnection struct {
	pool *fakePool
	once atomic.Bool
}

func (*fakeConnection) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, ErrUnavailable
}

func (c *fakeConnection) Release() {
	if c.once.CompareAndSwap(false, true) {
		<-c.pool.leases
	}
}

func cleanupRegistry(t *testing.T, r *Registry) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		require.NoError(t, r.Close(ctx))
	})
}

func TestRegistrySingleFlightAndReuse(t *testing.T) {
	var opens atomic.Int32
	p := &fakePool{leases: make(chan struct{}, 1)}
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
	for range 8 {
		go func() {
			results <- r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil })
		}()
	}
	<-opening
	close(proceed)
	for range 8 {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, 1, opens.Load())
	require.False(t, p.closed.Load())
	require.Empty(t, p.leases)
}

func TestRegistryActiveLeaseSurvivesInvalidationAndShutdown(t *testing.T) {
	p := &fakePool{leases: make(chan struct{}, 1)}
	var opens atomic.Int32
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) {
		opens.Add(1)
		return p, nil
	})
	cleanupRegistry(t, r)
	entered, finish, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- r.Use(t.Context(), testKey(), func(context.Context, Database) error {
			close(entered)
			<-finish
			return nil
		})
	}()
	<-entered
	r.Invalidate(testKey())
	require.False(t, p.closed.Load())
	next := testKey()
	next.Generation++
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	err := r.Use(ctx, next, func(context.Context, Database) error { t.Error("active slot must stay reserved"); return nil })
	cancel()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 1, opens.Load())
	ctx, cancel = context.WithTimeout(t.Context(), 10*time.Millisecond)
	require.ErrorIs(t, r.Close(ctx), context.DeadlineExceeded)
	cancel()
	require.False(t, p.closed.Load())
	require.ErrorIs(t, r.Use(t.Context(), next, func(context.Context, Database) error { return nil }), ErrClosed)
	close(finish)
	require.NoError(t, <-result)
	require.NoError(t, r.Close(t.Context()))
	require.True(t, p.closed.Load())
}

func TestRegistrySnapshotEvictionAndErrorRelease(t *testing.T) {
	var pools []*fakePool
	var keys []Key
	r := newRegistry(testConfig(), func(_ context.Context, key Key) (pool, error) {
		p := &fakePool{leases: make(chan struct{}, 1)}
		pools = append(pools, p)
		keys = append(keys, key)
		return p, nil
	})
	cleanupRegistry(t, r)
	callbackErr := errors.New("callback failed")
	for i := range 3 {
		key := testKey()
		key.Version += int64(i)
		key.Generation += int64(i)
		require.ErrorIs(t, r.Use(t.Context(), key, func(context.Context, Database) error { return callbackErr }), callbackErr)
	}
	require.Len(t, pools, 3)
	require.True(t, pools[0].closed.Load())
	require.True(t, pools[1].closed.Load())
	require.False(t, pools[2].closed.Load())
	require.NotEqual(t, keys[0], keys[1])
	// A stale invalidation must not close the new snapshot.
	r.Invalidate(keys[0])
	require.False(t, pools[2].closed.Load())
}

func TestRegistryBoundedAcquiringAndCancelledOpen(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAcquiring = 1
	started := make(chan struct{})
	r := newRegistry(cfg, func(ctx context.Context, _ Key) (pool, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	cleanupRegistry(t, r)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- r.Use(ctx, testKey(), func(context.Context, Database) error { return nil }) }()
	<-started
	require.ErrorIs(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }), ErrBusy)
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
	require.Eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.entries) == 0
	}, time.Second, time.Millisecond)
}

func TestRegistryIdleCleanup(t *testing.T) {
	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Millisecond
	p := &fakePool{leases: make(chan struct{}, 1)}
	r := newRegistry(cfg, func(context.Context, Key) (pool, error) { return p, nil })
	cleanupRegistry(t, r)
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
	require.Eventually(t, p.closed.Load, time.Second, time.Millisecond)
}

func TestRegistryFailedOpenCanRetry(t *testing.T) {
	var attempts int
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("secret transport error")
		}
		return &fakePool{leases: make(chan struct{}, 1)}, nil
	})
	cleanupRegistry(t, r)
	err := r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil })
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotContains(t, err.Error(), "secret")
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
}

type blockingClosePool struct {
	*fakePool
	started chan struct{}
	finish  chan struct{}
}

func (p *blockingClosePool) Close() {
	close(p.started)
	<-p.finish
	p.fakePool.Close()
}

func TestRegistryClosingPoolKeepsBudgetWithoutBlockingShutdownDeadline(t *testing.T) {
	p := &blockingClosePool{fakePool: &fakePool{leases: make(chan struct{}, 1)}, started: make(chan struct{}), finish: make(chan struct{})}
	var opens atomic.Int32
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) {
		opens.Add(1)
		return p, nil
	})
	cleanupRegistry(t, r)
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
	r.Invalidate(testKey())
	<-p.started
	next := testKey()
	next.Generation++
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	require.ErrorIs(t, r.Use(ctx, next, func(context.Context, Database) error { return nil }), context.DeadlineExceeded)
	cancel()
	require.EqualValues(t, 1, opens.Load(), "closing pool must still count against the SQL budget")
	ctx, cancel = context.WithTimeout(t.Context(), 10*time.Millisecond)
	require.ErrorIs(t, r.Close(ctx), context.DeadlineExceeded)
	cancel()
	close(p.finish)
	require.NoError(t, r.Close(t.Context()))
}
