package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CapacityConfig struct {
	MaxInFlight    int           `env:"HTTP_MAX_IN_FLIGHT" env-default:"128"`
	RequestTimeout time.Duration `env:"HTTP_REQUEST_TIMEOUT" env-default:"10s"`
}

func (c CapacityConfig) Validate() error {
	if c.MaxInFlight < 1 || c.MaxInFlight > 10000 || c.RequestTimeout < time.Second || c.RequestTimeout > 10*time.Second {
		return fmt.Errorf("HTTP capacity must be 1..10000 and request timeout 1s..10s")
	}
	return nil
}

func Admission(cfg CapacityConfig) func(http.Handler) http.Handler {
	slots := make(chan struct{}, cfg.MaxInFlight)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health/live" {
				next.ServeHTTP(w, r)
				return
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Retry-After", "1")
				if r.URL.Path == "/health/ready" {
					httpx.JSON(w, 503, struct {
						Status string `json:"status"`
					}{Status: "unavailable"})
					return
				}
				httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), cfg.RequestTimeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
