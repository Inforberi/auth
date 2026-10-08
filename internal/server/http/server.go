package httpserver

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func Run(ctx context.Context, log *zap.Logger, cfg Config, handler http.Handler) error {
	srv := http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return run(ctx, log, &srv, srv.ListenAndServe)
}
