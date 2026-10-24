package runtime

import (
	"context"
	"errors"
	"sync"
	"time"
)

type entry struct {
	key     Key
	pool    pool
	refs    int
	idleAt  time.Time
	retired bool
	closing bool
}

type Registry struct {
	mu       sync.Mutex
	config   Config
	open     opener
	entries  map[Key]*entry
	changed  chan struct{}
	stopping chan struct{}
	done     chan struct{}
	acquires chan struct{}
	closed   bool
}

func newRegistry(cfg Config, open opener) *Registry {
	r := &Registry{
		config: cfg, open: open, entries: make(map[Key]*entry), changed: make(chan struct{}),
		stopping: make(chan struct{}), done: make(chan struct{}), acquires: make(chan struct{}, cfg.MaxAcquiring),
	}
	go r.cleanIdle()
	return r
}

// Use owns the lease through the callback. Finish transactions before returning;
// neither the database nor its transactions may escape into asynchronous work.
func (r *Registry) Use(ctx context.Context, key Key, use func(context.Context, Database) error) error {
	if !key.Valid() || use == nil {
		return ErrUnavailable
	}
	select {
	case r.acquires <- struct{}{}:
	default:
		return ErrBusy
	}
	acquireCtx, cancel := context.WithTimeout(ctx, r.config.AcquireTimeout)
	e, err := r.borrow(acquireCtx, key)
	if err != nil {
		cancel()
		<-r.acquires
		return err
	}
	c, err := e.pool.acquire(acquireCtx)
	acquireErr := acquireCtx.Err()
	cancel()
	<-r.acquires
	if err != nil {
		r.release(e)
		return errors.Join(ErrUnavailable, acquireErr)
	}
	defer r.release(e)
	defer c.Release()
	return use(ctx, c)
}

func (r *Registry) borrow(ctx context.Context, key Key) (*entry, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(ErrBusy, err)
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return nil, ErrClosed
		}
		if e := r.entries[key]; e != nil && e.pool != nil && !e.retired {
			e.refs++
			r.mu.Unlock()
			return e, nil
		}
		if r.entries[key] == nil && len(r.entries) < r.config.MaxRuntimes {
			e := &entry{key: key, refs: 1}
			r.entries[key] = e
			r.mu.Unlock()
			return r.openEntry(ctx, e)
		}
		if old := r.evictable(key); old != nil {
			old.retired = true
			r.mu.Unlock()
			r.dispose(old)
			continue
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, errors.Join(ErrBusy, ctx.Err())
		case <-r.stopping:
			return nil, ErrClosed
		case <-changed:
		}
	}
}

// Called with mu held. Opening and closing pools still occupy their slots.
func (r *Registry) evictable(requested Key) *entry {
	if r.entries[requested] != nil {
		return nil
	}
	var oldest *entry
	for _, e := range r.entries {
		if e.pool != nil && e.refs == 0 && !e.retired && (oldest == nil || e.idleAt.Before(oldest.idleAt)) {
			oldest = e
		}
	}
	return oldest
}
