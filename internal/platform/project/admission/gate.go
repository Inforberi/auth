package admission

import (
	"context"
	"sync"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/redislimit"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type minuteLimiter func(context.Context, []redislimit.Budget) (bool, error)

type Gate struct {
	mu       sync.Mutex
	config   Config
	limit    minuteLimiter
	active   int
	actors   map[domain.ID]int
	projects map[string]int
}

func New(client *redis.Client, realm domain.ID, cfg Config) (*Gate, error) {
	if client == nil {
		return nil, ErrUnavailable
	}
	scope, err := realmscope.New("platform", string(realm))
	if err != nil {
		return nil, ErrUnavailable
	}
	prefix, err := scope.RedisPrefix("platform-project-admission", "")
	if err != nil {
		return nil, ErrUnavailable
	}
	return newGate(cfg, func(ctx context.Context, budgets []redislimit.Budget) (bool, error) {
		return redislimit.AllowMinute(ctx, client, prefix, budgets)
	})
}

func newGate(cfg Config, limiter minuteLimiter) (*Gate, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if limiter == nil {
		return nil, ErrUnavailable
	}
	return &Gate{config: cfg, limit: limiter, actors: make(map[domain.ID]int), projects: make(map[string]int)}, nil
}

// Acquire is capacity accounting, not authorization. The handler still performs
// its current SQL guard. Empty project identifies the shared catalog collection.
func (g *Gate) Acquire(ctx context.Context, actor, project domain.ID) (func(), error) {
	if !domain.ValidID(actor) {
		return nil, ErrUnavailable
	}
	if project != "" && !domain.ValidID(project) {
		return nil, domain.ErrInvalidProject
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	lane := string(project)
	if lane == "" {
		lane = "catalog"
	}
	g.mu.Lock()
	if g.active >= g.config.MaxInFlight || g.actors[actor] >= g.config.PerActorInFlight || g.projects[lane] >= g.config.PerProjectInFlight {
		g.mu.Unlock()
		return nil, ErrBusy
	}
	g.active++
	g.actors[actor]++
	g.projects[lane]++
	g.mu.Unlock()
	release := sync.OnceFunc(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.active--
		g.actors[actor]--
		g.projects[lane]--
		if g.actors[actor] == 0 {
			delete(g.actors, actor)
		}
		if g.projects[lane] == 0 {
			delete(g.projects, lane)
		}
	})
	allowed, err := g.limit(ctx, []redislimit.Budget{
		{Key: "global", Count: g.config.GlobalPerMinute},
		{Key: "actor:" + string(actor), Count: g.config.ActorPerMinute},
		{Key: "project:" + lane, Count: g.config.ProjectPerMinute},
	})
	if err != nil || ctx.Err() != nil {
		release()
		return nil, ErrUnavailable
	}
	if !allowed {
		release()
		return nil, ErrRateLimited
	}
	return release, nil
}
