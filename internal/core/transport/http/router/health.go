package router

import (
	"context"
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
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
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if check == nil || check(ctx) != nil {
			httpx.JSON(w, http.StatusServiceUnavailable, HealthResponse{Status: "unavailable"})
			return
		}
		httpx.JSON(w, http.StatusOK, HealthResponse{Status: "ok"})
	}
}
