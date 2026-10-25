package http

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func (d *RuntimeDispatcher) get(ctx context.Context, selected RuntimeSelection) (*runtimeRouteEntry, error) {
	now := time.Now()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, domain.ErrUnavailable
	}
	entry := d.entries[selected.Origin()]
	if entry != nil && entry.key == selected.Key() {
		if entry.routes == nil {
			d.mu.Unlock()
			return nil, domain.ErrUnavailable
		}
		if now.Sub(entry.created) < d.cfg.MaxAge {
			entry.used = now
			d.mu.Unlock()
			return entry, nil
		}
	}
	// A loading entry is not evicted, even if a newer key arrives mid-build.
	if entry != nil && entry.routes == nil || d.building >= d.cfg.MaxBuilding {
		d.mu.Unlock()
		return nil, domain.ErrUnavailable
	}
	if entry == nil && len(d.entries) >= d.cfg.MaxProfiles && !d.evict() {
		d.mu.Unlock()
		return nil, domain.ErrUnavailable
	}
	entry = &runtimeRouteEntry{key: selected.Key(), used: now}
	d.entries[selected.Origin()] = entry
	d.building++
	d.mu.Unlock()

	build, cancel := context.WithTimeout(ctx, d.cfg.BuildTimeout)
	routes, err := d.load(build, selected.Key(), selected.Origin())
	if err == nil && routes == nil {
		err = domain.ErrUnavailable
	}
	if err == nil {
		err = build.Err()
	}
	cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.building--
	if err != nil || d.closed {
		if d.entries[selected.Origin()] == entry {
			delete(d.entries, selected.Origin())
		}
		if err == nil {
			err = domain.ErrUnavailable
		}
		return nil, err
	}
	entry.routes, entry.created = routes, time.Now()
	return entry, nil
}

// evict only drops immutable assembly references; it never closes a shared dependency.
func (d *RuntimeDispatcher) evict() bool {
	var oldest string
	var used time.Time
	for origin, entry := range d.entries {
		if entry.routes != nil && (oldest == "" || entry.used.Before(used)) {
			oldest, used = origin, entry.used
		}
	}
	if oldest == "" {
		return false
	}
	delete(d.entries, oldest)
	return true
}

func (d *RuntimeDispatcher) remove(origin string, expected *runtimeRouteEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.entries[origin] == expected {
		delete(d.entries, origin)
	}
}
