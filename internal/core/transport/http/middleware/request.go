package core_middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/core/infra/logger"
)

func RequestLogger(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			var idBytes [16]byte
			_, _ = rand.Read(idBytes[:])
			id := hex.EncodeToString(idBytes[:])
			w.Header().Set("X-Request-ID", id)
			requestLog := log.With(zap.String("request_id", id))
			r = r.WithContext(logger.WithContext(r.Context(), requestLog))
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func(ctx context.Context) {
				status := ww.Status()
				if status == 0 {
					status = http.StatusOK
				}
				route := "unmatched"
				if rc := chi.RouteContext(ctx); rc != nil && rc.RoutePattern() != "" {
					route = rc.RoutePattern()
				}
				requestLog.Info("request completed", zap.String("method", r.Method), zap.String("route", route), zap.Int("status", status), zap.Int("bytes", ww.BytesWritten()), zap.Duration("duration", time.Since(start)))
			}(r.Context())
			next.ServeHTTP(ww, r)
		})
	}
}
