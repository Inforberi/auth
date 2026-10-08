package auth

import (
	"context"
	"sync"
)

type App struct {
	serve     func(context.Context) error
	resources *resources
}

func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	return a.serve(ctx)
}

// Close is idempotent. Normally Run closes the application; callers that do not
// start it must call Close themselves. Do not close it while Run is active.
func (a *App) Close() {
	a.resources.close()
}

type resources struct {
	once    sync.Once
	closers []func()
}

func (r *resources) add(close func()) {
	r.closers = append(r.closers, close)
}

func (r *resources) close() {
	r.once.Do(func() {
		for i := len(r.closers) - 1; i >= 0; i-- {
			r.closers[i]()
		}
	})
}
