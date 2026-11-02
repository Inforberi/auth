package admission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/redislimit"
)

const (
	actorA   domain.ID = "11111111-1111-4111-8111-111111111111"
	actorB   domain.ID = "22222222-2222-4222-8222-222222222222"
	projectA domain.ID = "33333333-3333-4333-8333-333333333333"
	projectB domain.ID = "44444444-4444-4444-8444-444444444444"
)

func allow(context.Context, []redislimit.Budget) (bool, error) { return true, nil }

func TestCapacityScopes(t *testing.T) {
	for _, scope := range []string{"actor", "project", "global", "catalog"} {
		t.Run(scope, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxInFlight, cfg.PerActorInFlight, cfg.PerProjectInFlight = 2, 1, 1
			g, err := newGate(cfg, allow)
			require.NoError(t, err)
			project := projectA
			if scope == "catalog" {
				project = ""
			}
			release, err := g.Acquire(t.Context(), actorA, project)
			require.NoError(t, err)
			switch scope {
			case "actor":
				_, err = g.Acquire(t.Context(), actorA, projectB)
			case "project", "catalog":
				_, err = g.Acquire(t.Context(), actorB, project)
			case "global":
				other, e := g.Acquire(t.Context(), actorB, projectB)
				require.NoError(t, e)
				_, err = g.Acquire(t.Context(), domain.ID("55555555-5555-4555-8555-555555555555"), "")
				other()
			}
			require.ErrorIs(t, err, ErrBusy)
			release()
			release()
			require.Zero(t, g.active)
			require.Empty(t, g.actors)
			require.Empty(t, g.projects)
			next, e := g.Acquire(t.Context(), actorA, project)
			require.NoError(t, e)
			next()
		})
	}
}

func TestAdmissionFailuresReleaseCapacity(t *testing.T) {
	for _, test := range []struct {
		name           string
		allowed        bool
		err, errorWant error
	}{
		{"rate", false, nil, ErrRateLimited}, {"outage", false, errors.New("backend down"), ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			g, err := newGate(DefaultConfig(), func(context.Context, []redislimit.Budget) (bool, error) { return test.allowed, test.err })
			require.NoError(t, err)
			for range 30 {
				release, e := g.Acquire(t.Context(), actorA, projectA)
				require.Nil(t, release)
				require.ErrorIs(t, e, test.errorWant)
			}
			require.Zero(t, g.active)
			require.Empty(t, g.actors)
			require.Empty(t, g.projects)
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	g, err := newGate(DefaultConfig(), func(context.Context, []redislimit.Budget) (bool, error) { cancel(); return true, nil })
	require.NoError(t, err)
	_, err = g.Acquire(ctx, actorA, projectA)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Zero(t, g.active)
	_, err = g.Acquire(ctx, actorA, projectA)
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = g.Acquire(t.Context(), actorA, "not-a-uuid")
	require.ErrorIs(t, err, domain.ErrInvalidProject)
	_, err = g.Acquire(t.Context(), "", projectA)
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestConcurrentAdmissionHasNoWaiters(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxInFlight, cfg.PerActorInFlight, cfg.PerProjectInFlight = 2, 2, 2
	entered, finish := make(chan struct{}, 2), make(chan struct{})
	g, err := newGate(cfg, func(context.Context, []redislimit.Budget) (bool, error) {
		entered <- struct{}{}
		<-finish
		return true, nil
	})
	require.NoError(t, err)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 2 {
		wg.Go(func() {
			release, e := g.Acquire(t.Context(), actorA, projectA)
			if e != nil {
				t.Error(e)
				return
			}
			accepted.Add(1)
			release()
		})
	}
	<-entered
	<-entered
	for range 30 {
		_, e := g.Acquire(t.Context(), actorB, projectB)
		require.ErrorIs(t, e, ErrBusy)
	}
	close(finish)
	wg.Wait()
	require.EqualValues(t, 2, accepted.Load())
	require.Zero(t, g.active)
	require.Empty(t, g.actors)
	require.Empty(t, g.projects)
}

func TestConfigBounds(t *testing.T) {
	require.NoError(t, DefaultConfig().Validate())
	for _, mutate := range []func(*Config){
		func(c *Config) { c.MaxInFlight = 0 }, func(c *Config) { c.PerActorInFlight = c.MaxInFlight + 1 },
		func(c *Config) { c.PerProjectInFlight = 0 }, func(c *Config) { c.GlobalPerMinute = 1 },
		func(c *Config) { c.ActorPerMinute = c.GlobalPerMinute }, func(c *Config) { c.ProjectPerMinute = 0 },
	} {
		cfg := DefaultConfig()
		mutate(&cfg)
		require.Error(t, cfg.Validate())
	}
}
