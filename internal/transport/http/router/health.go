package router

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type HealthResponse struct {
	Status string `json:"status"`
}

// @Summary Process liveness
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health/live [get]
func live(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}

// @Summary PostgreSQL and Redis readiness
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 503 {object} HealthResponse
// @Router /health/ready [get]
func readiness(check func(context.Context) error) http.HandlerFunc {
	var mu sync.Mutex
	var running chan struct{}
	var checkedAt time.Time
	healthy := false
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for {
			mu.Lock()
			if time.Since(checkedAt) < time.Second {
				ok := healthy
				mu.Unlock()
				writeReadiness(w, ok)
				return
			}
			if running != nil {
				done := running
				mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					writeReadiness(w, false)
					return
				}
			}
			running = make(chan struct{})
			mu.Unlock()
			ok := check != nil && check(ctx) == nil
			mu.Lock()
			healthy, checkedAt = ok, time.Now()
			close(running)
			running = nil
			mu.Unlock()
			writeReadiness(w, ok)
			return
		}
	}
}

func writeReadiness(w http.ResponseWriter, healthy bool) {
	if !healthy {
		httpx.JSON(w, http.StatusServiceUnavailable, HealthResponse{Status: "unavailable"})
		return
	}
	httpx.JSON(w, http.StatusOK, HealthResponse{Status: "ok"})
}
