package auth

import (
	"context"
	"errors"
	stdlog "log"
	"reflect"
	"testing"

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
