package runtime

import (
	"context"
	"time"
)

const StateBatchSize = 128

type StateReader interface {
	CurrentRuntimes(context.Context, []Key) ([]bool, error)
}

// StartSync checks only resident snapshots. SQL remains the operation authority;
// polling is resource invalidation, never a cached grant or session-revoke delay.
func (r *Registry) StartSync(parent context.Context, reader StateReader, interval, timeout time.Duration) error {
	if reader == nil || interval <= 0 || timeout <= 0 {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.syncDone != nil {
		return ErrClosed
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	r.syncCancel, r.syncDone = cancel, make(chan struct{})
	go func() {
		defer close(r.syncDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				probe, stop := context.WithTimeout(ctx, timeout)
				r.syncResident(probe, reader)
				stop()
			}
		}
	}()
	return nil
}

func (r *Registry) syncResident(ctx context.Context, reader StateReader) {
	r.mu.Lock()
	entries := make([]*entry, 0, len(r.entries))
	keys := make([]Key, 0, len(r.entries))
	for key, e := range r.entries {
		if !e.retired {
			entries, keys = append(entries, e), append(keys, key)
		}
	}
	r.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	current := make([]bool, 0, len(keys))
	for start := 0; start < len(keys); start += StateBatchSize {
		end := min(start+StateBatchSize, len(keys))
		batch, err := reader.CurrentRuntimes(ctx, keys[start:end])
		if err != nil || len(batch) != end-start {
			current = nil // Unavailable/incomplete evidence must not extend reuse.
			break
		}
		current = append(current, batch...)
	}
	if ctx.Err() != nil {
		current = nil
	}
	r.mu.Lock()
	var idle []*entry
	for i, e := range entries {
		if r.entries[e.key] != e || e.retired || (len(current) == len(entries) && current[i]) {
			continue
		}
		e.retired = true
		if e.refs == 0 && e.pool != nil {
			idle = append(idle, e)
		}
	}
	r.signal()
	r.mu.Unlock()
	for _, e := range idle {
		r.dispose(e)
	}
}
