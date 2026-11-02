package http

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type RuntimeRoutes interface {
	http.Handler
	CheckCurrent(context.Context) error
}

type RuntimeRouteLoader func(context.Context, projectruntime.Key, string) (RuntimeRoutes, error)

type RuntimeDispatcherConfig struct {
	MaxProfiles  int
	MaxBuilding  int
	BuildTimeout time.Duration
	MaxAge       time.Duration
}

type runtimeRouteEntry struct {
	key           projectruntime.Key
	routes        RuntimeRoutes
	created, used time.Time
}

type RuntimeDispatcher struct {
	mu       sync.Mutex
	cfg      RuntimeDispatcherConfig
	load     RuntimeRouteLoader
	entries  map[string]*runtimeRouteEntry
	building int
	active   int
	closed   bool
	drained  chan struct{}
}

func NewRuntimeDispatcher(cfg RuntimeDispatcherConfig, load RuntimeRouteLoader) (*RuntimeDispatcher, error) {
	if load == nil || cfg.MaxProfiles < 1 || cfg.MaxProfiles > 256 || cfg.MaxBuilding < 1 || cfg.MaxBuilding > cfg.MaxProfiles || cfg.BuildTimeout <= 0 || cfg.BuildTimeout > 30*time.Second || cfg.MaxAge < time.Second || cfg.MaxAge > 5*time.Minute {
		return nil, domain.ErrInvalidProject
	}
	return &RuntimeDispatcher{cfg: cfg, load: load, entries: make(map[string]*runtimeRouteEntry), drained: make(chan struct{})}, nil
}

func (d *RuntimeDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	selected, ok := RuntimeFromContext(r.Context())
	if !ok || !d.enter() {
		runtimeUnavailable(w)
		return
	}
	defer d.leave()
	entry, err := d.get(r.Context(), selected)
	if err == nil {
		err = entry.routes.CheckCurrent(r.Context())
	}
	if err != nil {
		if entry != nil {
			d.remove(selected.Origin(), entry)
		}
		if errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrNotFound) || errors.Is(err, settingsdomain.ErrPolicyConflict) {
			http.NotFound(w, r)
		} else {
			runtimeUnavailable(w)
		}
		return
	}
	entry.routes.ServeHTTP(w, r)
}

func (d *RuntimeDispatcher) enter() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.active++
	return true
}

func (d *RuntimeDispatcher) leave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active--
	if d.closed && d.active == 0 {
		close(d.drained)
	}
}

// Close stops admission and drains requests; shared SQL/Redis owners close afterwards.
func (d *RuntimeDispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		clear(d.entries)
		if d.active == 0 {
			close(d.drained)
		}
	}
	d.mu.Unlock()
	select {
	case <-d.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
