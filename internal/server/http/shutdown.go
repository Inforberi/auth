package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func run(ctx context.Context, log *zap.Logger, srv *http.Server, serve func() error) error {
	serverErr := make(chan error, 1)

	go func() {
		log.Info("Start server")

		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}

		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	return shutdown(ctx, log, srv, 10*time.Second)
}

// Shutdown gets its own deadline: the signal context is already cancelled.
func shutdown(ctx context.Context, log *zap.Logger, srv *http.Server, timeout time.Duration) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		if closeErr := srv.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return fmt.Errorf("shutdown http server: %w", err)
	}

	log.Info("http server stopped gracefully")

	return nil
}
