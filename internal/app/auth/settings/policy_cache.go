package settings

import (
	"context"
	"sync"
	"time"
)

// A bounded refresh coalesces requests while keeping policy changes visible to all replicas.
func cachedPolicy[P comparable](load func(context.Context) (P, error)) (func(context.Context) (P, error), func()) {
	var mu sync.RWMutex
	var value P
	var expires time.Time
	var loadErr error

	return func(ctx context.Context) (P, error) {
			mu.RLock()
			if time.Now().Before(expires) {
				current, err := value, loadErr
				mu.RUnlock()
				return current, err
			}
			mu.RUnlock()

			mu.Lock()
			defer mu.Unlock()
			if time.Now().Before(expires) {
				return value, loadErr
			}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			current, err := load(ctx)
			if err != nil {
				return current, err
			}
			value, expires = current, time.Now().Add(time.Second)
			return value, nil
		}, func() {
			mu.Lock()
			defer mu.Unlock()
			expires = time.Time{}
		}
}
