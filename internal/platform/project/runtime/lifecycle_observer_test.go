package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestObserveKeepsActiveLeaseAndDoesNotRetireNewerOrForeignRuntime(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRuntimes, cfg.ConnectionBudget = 3, 3
	pools := make(map[Key]*fakePool)
	r := newRegistry(cfg, func(_ context.Context, key Key) (pool, error) {
		p := &fakePool{leases: make(chan struct{}, 1)}
		pools[key] = p
		return p, nil
	})
	cleanupRegistry(t, r)
	old := testKey()
	entered, finish, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- r.Use(t.Context(), old, func(context.Context, Database) error { close(entered); <-finish; return nil })
	}()
	<-entered
	newer := old
	newer.Version, newer.Generation = 3, 3
	foreign := old
	foreign.Binding.RealmID = "c2000000-0000-4000-8000-000000000002"
	for _, key := range []Key{newer, foreign} {
		require.NoError(t, r.Use(t.Context(), key, func(context.Context, Database) error { return nil }))
	}
	change := domain.TransitionReceipt{ProjectID: old.Binding.ProjectID, Version: 2, Generation: 2, DesiredState: domain.Suspended, Phase: domain.Ready}
	r.Observe(old.Binding.RealmID, change)
	require.False(t, pools[old].closed.Load(), "active work must retain its pool")
	require.False(t, pools[newer].closed.Load(), "delayed replay must not retire a newer generation")
	require.False(t, pools[foreign].closed.Load(), "realm boundary must remain exact")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	require.ErrorIs(t, r.Use(ctx, old, func(context.Context, Database) error { t.Error("retired snapshot was reissued"); return nil }), context.DeadlineExceeded)
	cancel()
	close(finish)
	require.NoError(t, <-result)
	require.Eventually(t, pools[old].closed.Load, time.Second, time.Millisecond)
	change.Version, change.Generation, change.DesiredState = 4, 4, domain.Enabled
	r.Observe(old.Binding.RealmID, change)
	require.Eventually(t, pools[newer].closed.Load, time.Second, time.Millisecond)
	require.False(t, pools[foreign].closed.Load())
}

func TestObserveDuringColdOpenDiscardsRetiredPool(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	p := &fakePool{leases: make(chan struct{}, 1)}
	r := newRegistry(testConfig(), func(ctx context.Context, _ Key) (pool, error) {
		close(started)
		select {
		case <-proceed:
			return p, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	cleanupRegistry(t, r)
	key := testKey()
	result := make(chan error, 1)
	go func() {
		result <- r.Use(t.Context(), key, func(context.Context, Database) error { t.Error("retired cold-open was published"); return nil })
	}()
	<-started
	r.Observe(key.Binding.RealmID, domain.TransitionReceipt{ProjectID: key.Binding.ProjectID, Version: 2, Generation: 2, DesiredState: domain.Enabled, Phase: domain.Ready})
	close(proceed)
	require.ErrorIs(t, <-result, ErrUnavailable)
	require.Eventually(t, p.closed.Load, time.Second, time.Millisecond)
}
