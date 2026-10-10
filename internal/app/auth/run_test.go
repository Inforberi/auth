package auth

import (
	"context"
	"errors"
	stdlog "log"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
)

func TestRunClosesResourcesAfterServer(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "serve failure"}[fail], func(t *testing.T) {
			var order []string
			owned := &resources{}
			for _, name := range []string{"logger", "postgres", "redis"} {
				owned.add(func() { order = append(order, name) })
			}
			failure := errors.New("serve failed")
			app := &App{resources: owned, serve: func(context.Context) error {
				if len(order) != 0 {
					t.Fatal("dependencies closed before server completed")
				}
				order = append(order, "server")
				if fail {
					return failure
				}
				return nil
			}}
			err := app.Run(t.Context())
			if fail && !errors.Is(err, failure) || !fail && err != nil {
				t.Fatalf("unexpected run error: %v", err)
			}
			app.Close()
			if !reflect.DeepEqual(order, []string{"server", "redis", "postgres", "logger"}) {
				t.Fatalf("wrong cleanup order or repeated cleanup: %v", order)
			}
		})
	}
}

func TestNewReleasesResourcesOnStartupFailure(t *testing.T) {
	writer, flags, prefix := stdlog.Writer(), stdlog.Flags(), stdlog.Prefix()
	cfg := &config.Config{Logger: logger.Config{Env: "test", Level: "error"}}
	// Missing PostgreSQL URL fails before opening any network connection.
	app, err := New(t.Context(), cfg)
	if err == nil || app != nil {
		t.Fatal("invalid startup unexpectedly succeeded")
	}
	if stdlog.Writer() != writer || stdlog.Flags() != flags || stdlog.Prefix() != prefix {
		t.Fatal("failed startup did not restore the standard logger")
	}
}

type testDeliveryWorker struct {
	started chan struct{}
	stopped chan struct{}
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

func (w *testDeliveryWorker) RunDelivery(ctx context.Context, _ func(error)) {
	close(w.started)
	<-ctx.Done()
	close(w.stopped)
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
			owned := &resources{}
			owned.add(func() {
				for _, worker := range workers {
					select {
					case <-worker.stopped:
					default:
						t.Error("resource closed before delivery stopped")
					}
				}
			})
			failure := errors.New("serve failure")
			app := &App{resources: owned, serve: func(ctx context.Context) error {
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
