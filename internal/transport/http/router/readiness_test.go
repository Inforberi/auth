package router

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReadinessCoalescesConcurrentProbes(t *testing.T) {
	var calls atomic.Int64
	started, release := make(chan struct{}), make(chan struct{})
	h := readiness(func(context.Context) error {
		calls.Add(1)
		close(started)
		<-release
		return nil
	})
	var probes sync.WaitGroup
	probes.Go(func() { h(httptest.NewRecorder(), httptest.NewRequest("GET", "/health/ready", nil)) })
	<-started
	for range 1000 {
		probes.Go(func() {
			w := httptest.NewRecorder()
			h(w, httptest.NewRequest("GET", "/health/ready", nil))
			if w.Code != 200 {
				t.Error("probe failed", w.Code)
			}
		})
	}
	close(release)
	probes.Wait()
	if calls.Load() != 1 {
		t.Fatal("readiness stampede", calls.Load())
	}
}
