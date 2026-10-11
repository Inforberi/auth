package delivery

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunStopsAndBoundsBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var calls, reports atomic.Int64
	go func() {
		defer close(done)
		Run(ctx, func(context.Context) (bool, error) {
			n := calls.Add(1)
			if n == 10 {
				cancel()
			}
			return true, errors.New("delivery failed")
		}, func(error) { reports.Add(1) })
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker failed to stop")
	}
	if calls.Load() != 10 || reports.Load() != 9 {
		t.Fatal(calls.Load(), reports.Load())
	}
}

func TestRunCanceledBeforeTick(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Run(ctx, func(context.Context) (bool, error) { t.Fatal("processed after cancellation"); return false, nil }, func(error) {})
}
