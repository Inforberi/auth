package auth

import (
	"sync"
)

type Resources struct {
	once    sync.Once
	closers []func()
}

func (r *Resources) Add(close func()) {
	if close != nil {
		r.closers = append(r.closers, close)
	}
}

func (r *Resources) Close() {
	r.once.Do(func() {
		for i := len(r.closers) - 1; i >= 0; i-- {
			r.closers[i]()
		}
	})
}
