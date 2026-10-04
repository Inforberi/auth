package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func Run(ctx context.Context, log *zap.Logger, cfg Config, hanlder http.Handler) error {
	srv := http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           hanlder,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return run(ctx, log, &srv, srv.ListenAndServe)
}

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

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
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
