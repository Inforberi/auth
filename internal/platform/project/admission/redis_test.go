package admission

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func TestRedisAdmissionAcrossInstances(t *testing.T) {
	addr := os.Getenv("AUTH_ADMISSION_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host, "dedicated localhost Redis required")
	one := redis.NewClient(&redis.Options{Addr: addr, DB: 14, MaxRetries: -1})
	two := redis.NewClient(&redis.Options{Addr: addr, DB: 14, MaxRetries: -1})
	t.Cleanup(func() { _ = one.Close(); _ = two.Close() })
	size, err := one.DBSize(t.Context()).Result()
	require.NoError(t, err)
	require.Zero(t, size, "disposable DB14 must be empty")
	cfg := DefaultConfig()
	cfg.MaxInFlight, cfg.PerActorInFlight, cfg.PerProjectInFlight = 64, 64, 64
	cfg.GlobalPerMinute, cfg.ActorPerMinute, cfg.ProjectPerMinute = 10, 4, 6
	a, err := New(one, actorA, cfg)
	require.NoError(t, err)
	b, err := New(two, actorA, cfg)
	require.NoError(t, err)
	scope, err := realmscope.New("platform", string(actorA))
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("platform-project-admission", "")
	require.NoError(t, err)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			gate := a
			if i%2 == 1 {
				gate = b
			}
			release, e := gate.Acquire(t.Context(), actorA, projectA)
			if e == nil {
				accepted.Add(1)
				release()
			} else if !errors.Is(e, ErrRateLimited) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 4, accepted.Load())
	count, err := one.Get(t.Context(), prefix+"global").Int()
	require.NoError(t, err)
	require.Equal(t, 4, count)
	ttl, err := one.PTTL(t.Context(), prefix+"actor:"+string(actorA)).Result()
	require.NoError(t, err)
	require.Positive(t, ttl)
	require.LessOrEqual(t, ttl, time.Minute)
	_, err = a.Acquire(t.Context(), actorA, projectB)
	require.ErrorIs(t, err, ErrRateLimited)
	exists, err := one.Exists(t.Context(), prefix+"project:"+string(projectB)).Result()
	require.NoError(t, err)
	require.Zero(t, exists, "denial must not allocate a new project counter")
	after, err := one.PTTL(t.Context(), prefix+"actor:"+string(actorA)).Result()
	require.NoError(t, err)
	require.LessOrEqual(t, after, ttl, "denial must not extend TTL")
	for range 2 {
		release, e := b.Acquire(t.Context(), actorB, projectA)
		require.NoError(t, e)
		release()
	}
	_, err = b.Acquire(t.Context(), actorB, projectA)
	require.ErrorIs(t, err, ErrRateLimited, "shared project quota exhausted")
	release, err := a.Acquire(t.Context(), actorB, projectB)
	require.NoError(t, err)
	release()
	count, err = one.Get(t.Context(), prefix+"global").Int()
	require.NoError(t, err)
	require.Equal(t, 7, count, "actor/project rejections must not charge global quota")
	actorC := projectA
	for range 3 {
		release, e := a.Acquire(t.Context(), actorC, projectB)
		require.NoError(t, e)
		release()
	}
	_, err = b.Acquire(t.Context(), actorC, projectB)
	require.ErrorIs(t, err, ErrRateLimited, "global quota is shared across instances")
	// Corrupt/no-TTL counters fail closed before any other counter is charged.
	require.NoError(t, one.Set(t.Context(), prefix+"global", "7", 0).Err())
	_, err = a.Acquire(t.Context(), actorB, projectB)
	require.ErrorIs(t, err, ErrUnavailable)
	otherRealm, err := New(one, actorB, cfg)
	require.NoError(t, err)
	release, err = otherRealm.Acquire(t.Context(), actorA, projectA)
	require.NoError(t, err, "a broken counter in another realm must not affect this realm")
	release()
	require.Zero(t, a.active)
	require.Zero(t, b.active)
	require.Empty(t, a.actors)
	require.Empty(t, b.projects)
	require.NoError(t, two.Close())
	_, err = b.Acquire(t.Context(), actorB, projectB)
	require.ErrorIs(t, err, ErrUnavailable)
}
