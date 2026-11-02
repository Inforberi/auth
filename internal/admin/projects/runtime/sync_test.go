package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type stateReaderFunc func(context.Context, []Key) ([]bool, error)

func (f stateReaderFunc) CurrentRuntimes(ctx context.Context, keys []Key) ([]bool, error) {
	return f(ctx, keys)
}

func TestSyncEmptyAndInvalidEvidence(t *testing.T) {
	for _, failure := range []string{"error", "incomplete", "mismatch"} {
		t.Run(failure, func(t *testing.T) {
			p := &fakePool{leases: make(chan struct{}, 1)}
			r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) { return p, nil })
			cleanupRegistry(t, r)
			calls := 0
			reader := stateReaderFunc(func(_ context.Context, keys []Key) ([]bool, error) {
				calls++
				require.Equal(t, []Key{testKey()}, keys)
				if failure == "error" {
					return nil, errors.New("catalog unavailable")
				}
				if failure == "incomplete" {
					return nil, nil
				}
				return []bool{false}, nil
			})
			r.syncResident(t.Context(), reader)
			require.Zero(t, calls)
			require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
			r.syncResident(t.Context(), reader)
			require.Equal(t, 1, calls)
			require.Eventually(t, p.closed.Load, time.Second, time.Millisecond)
		})
	}
}

func TestStaleSyncResponseCannotRetireReopenedEntry(t *testing.T) {
	var pools []*fakePool
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) {
		p := &fakePool{leases: make(chan struct{}, 1)}
		pools = append(pools, p)
		return p, nil
	})
	cleanupRegistry(t, r)
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		r.syncResident(t.Context(), stateReaderFunc(func(context.Context, []Key) ([]bool, error) { close(entered); <-release; return []bool{false}, nil }))
		close(done)
	}()
	<-entered
	r.Invalidate(testKey())
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
	close(release)
	<-done
	require.Len(t, pools, 2)
	require.True(t, pools[0].closed.Load())
	require.False(t, pools[1].closed.Load())
}

func TestCloseCancelsAndJoinsSync(t *testing.T) {
	p := &fakePool{leases: make(chan struct{}, 1)}
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) { return p, nil })
	cleanupRegistry(t, r)
	require.NoError(t, r.Use(t.Context(), testKey(), func(context.Context, Database) error { return nil }))
	entered := make(chan struct{})
	var exited atomic.Bool
	reader := stateReaderFunc(func(ctx context.Context, _ []Key) ([]bool, error) {
		close(entered)
		<-ctx.Done()
		exited.Store(true)
		return nil, ctx.Err()
	})
	require.NoError(t, r.StartSync(t.Context(), reader, time.Millisecond, time.Second))
	require.Error(t, r.StartSync(t.Context(), reader, time.Millisecond, time.Second))
	<-entered
	require.NoError(t, r.Close(t.Context()))
	require.True(t, exited.Load())
	require.True(t, p.closed.Load())
}

func TestSyncKeepsActiveLease(t *testing.T) {
	p := &fakePool{leases: make(chan struct{}, 1)}
	r := newRegistry(testConfig(), func(context.Context, Key) (pool, error) { return p, nil })
	cleanupRegistry(t, r)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- r.Use(t.Context(), testKey(), func(context.Context, Database) error { close(entered); <-release; return nil })
	}()
	<-entered
	r.syncResident(t.Context(), stateReaderFunc(func(context.Context, []Key) ([]bool, error) { return []bool{false}, nil }))
	require.False(t, p.closed.Load())
	close(release)
	require.NoError(t, <-done)
	require.Eventually(t, p.closed.Load, time.Second, time.Millisecond)
}

func TestSyncBatchesAndRejectsPartialCycle(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRuntimes, cfg.ConnectionBudget = StateBatchSize+1, StateBatchSize+1
	var pools []*fakePool
	r := newRegistry(cfg, func(context.Context, Key) (pool, error) {
		p := &fakePool{leases: make(chan struct{}, 1)}
		pools = append(pools, p)
		return p, nil
	})
	cleanupRegistry(t, r)
	for i := range StateBatchSize + 1 {
		key := testKey()
		key.Version += int64(i)
		require.NoError(t, r.Use(t.Context(), key, func(context.Context, Database) error { return nil }))
	}
	var sizes []int
	r.syncResident(t.Context(), stateReaderFunc(func(_ context.Context, keys []Key) ([]bool, error) {
		sizes = append(sizes, len(keys))
		if len(sizes) > 1 {
			return nil, errors.New("later batch failed")
		}
		current := make([]bool, len(keys))
		for i := range current {
			current[i] = true
		}
		return current, nil
	}))
	require.Equal(t, []int{StateBatchSize, 1}, sizes)
	require.Eventually(t, func() bool {
		for _, p := range pools {
			if !p.closed.Load() {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond, "partial evidence cannot keep earlier batches reusable")
}
