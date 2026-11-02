package runtime

import (
	"context"
	"errors"
	"time"
)

func (r *Registry) openEntry(ctx context.Context, e *entry) (*entry, error) {
	openCtx, cancel := context.WithTimeout(ctx, r.config.OpenTimeout)
	p, err := r.open(openCtx, e.key)
	cancel()
	r.mu.Lock()
	e.pool = p
	if err != nil || p == nil || r.closed || e.retired || ctx.Err() != nil {
		e.retired, e.refs = true, 0
		r.mu.Unlock()
		r.dispose(e)
		return nil, errors.Join(ErrUnavailable, ctx.Err())
	}
	r.signal()
	r.mu.Unlock()
	return e, nil
}

func (r *Registry) release(e *entry) {
	r.mu.Lock()
	e.refs--
	e.idleAt = time.Now()
	dispose := e.refs == 0 && e.retired
	r.signal()
	r.mu.Unlock()
	if dispose {
		r.dispose(e)
	}
}

func (r *Registry) signal() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *Registry) dispose(e *entry) {
	r.mu.Lock()
	if e.closing {
		r.mu.Unlock()
		return
	}
	e.closing = true
	p := e.pool
	r.mu.Unlock()
	// pgxpool.Close may wait for a cancelled connection constructor. Keep the
	// slot reserved until it finishes, without blocking Close(ctx)'s deadline.
	go func() {
		if p != nil {
			p.Close()
		}
		r.mu.Lock()
		delete(r.entries, e.key)
		r.signal()
		if r.closed && len(r.entries) == 0 {
			close(r.done)
		}
		r.mu.Unlock()
	}()
}

// Invalidate retires exactly one snapshot; it never redirects active work.
func (r *Registry) Invalidate(key Key) {
	r.mu.Lock()
	e := r.entries[key]
	dispose := false
	if e != nil && !e.retired {
		e.retired = true
		dispose = e.refs == 0 && e.pool != nil
	}
	r.signal()
	r.mu.Unlock()
	if dispose {
		r.dispose(e)
	}
}

func (r *Registry) Close(ctx context.Context) error {
	r.mu.Lock()
	var idle []*entry
	if !r.closed {
		r.closed = true
		close(r.stopping)
		if r.syncCancel != nil {
			r.syncCancel()
		}
		for _, e := range r.entries {
			if !e.retired && e.refs == 0 && e.pool != nil {
				idle = append(idle, e)
			}
			e.retired = true
		}
		if len(r.entries) == 0 {
			close(r.done)
		}
		r.signal()
	}
	worker := r.syncDone
	r.mu.Unlock()
	for _, e := range idle {
		r.dispose(e)
	}
	if worker != nil {
		select {
		case <-worker:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Registry) cleanIdle() {
	ticker := time.NewTicker(min(r.config.IdleTimeout, time.Minute))
	defer ticker.Stop()
	for {
		select {
		case <-r.stopping:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			var idle []*entry
			for _, e := range r.entries {
				if !e.retired && e.pool != nil && e.refs == 0 && now.Sub(e.idleAt) >= r.config.IdleTimeout {
					e.retired = true
					idle = append(idle, e)
				}
			}
			r.mu.Unlock()
			for _, e := range idle {
				r.dispose(e)
			}
		}
	}
}
