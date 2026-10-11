package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		if r.URL.Path != "/swagger" && !strings.HasPrefix(r.URL.Path, "/swagger/") {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func Recoverer(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func(ctx context.Context) {
				if recovered := recover(); recovered != nil {
					if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
						panic(http.ErrAbortHandler)
					}
					// Panic values and stack arguments can contain credentials.
					logger.FromContext(ctx, log).Error("request panicked")
					w.Header().Set("Cache-Control", "no-store")
					httpx.Error(w, http.StatusInternalServerError, "internal_error", "internal error")
				}
			}(r.Context())
			next.ServeHTTP(w, r)
		})
	}
}
