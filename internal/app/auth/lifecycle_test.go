package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type testDeliveryWorker struct {
	started chan struct{}
	stopped chan struct{}
	err     error
}

func TestBackgroundCancellationJoinsWorker(t *testing.T) {
	stopped := make(chan struct{})
	stop := startBackground(t.Context(), func(ctx context.Context) {
		<-ctx.Done()
		close(stopped)
	})
	stop()
	select {
	case <-stopped:
	default:
		t.Fatal("background worker not joined")
	}
}

func (w *testDeliveryWorker) RunDelivery(ctx context.Context, report func(error)) {
	close(w.started)
	if w.err != nil {
		report(w.err)
	}
	<-ctx.Done()
	close(w.stopped)
}

func TestSecurityDeliveryReportsWithoutDependencyDetails(t *testing.T) {
	for _, err := range []error{domain.ErrSecurityDelivery, errors.New("smtp-private-password")} {
		core, logs := observer.New(zap.DebugLevel)
		worker := &testDeliveryWorker{started: make(chan struct{}), stopped: make(chan struct{}), err: err}
		stop := startDelivery(t.Context(), worker, zap.New(core))
		<-worker.started
		stop()
		entries := logs.All()
		if len(entries) != 1 || strings.Contains(entries[0].Message, "private-password") || len(entries[0].Context) != 0 {
			t.Fatal("unsafe delivery log", entries)
		}
		if errors.Is(err, domain.ErrSecurityDelivery) && entries[0].Level != zap.ErrorLevel {
			t.Fatal("security delivery error is not actionable")
		}
	}
}

func TestDeliveryStopsBeforeResourcesClose(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "serve failure"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			workers := []*testDeliveryWorker{
				{started: make(chan struct{}), stopped: make(chan struct{})},
				{started: make(chan struct{}), stopped: make(chan struct{})},
			}
			owned := &Resources{}
			owned.Add(func() {
				for _, worker := range workers {
					select {
					case <-worker.stopped:
					default:
						t.Error("resource closed before delivery stopped")
					}
				}
			})
			failure := errors.New("serve failure")
			app := &testApplication{resources: owned, serve: func(ctx context.Context) error {
				return runWithDelivery(ctx, zap.NewNop(), func(ctx context.Context) error {
					for _, worker := range workers {
						select {
						case <-worker.started:
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if fail {
						return failure
					}
					return nil
				}, workers[0], workers[1])
			}}
			err := app.Run(ctx)
			if fail && !errors.Is(err, failure) || !fail && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
