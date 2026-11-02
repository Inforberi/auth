package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/admission"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type capacityGate interface {
	Acquire(context.Context, domain.ID, domain.ID) (func(), error)
}

// Capacity must run after session validation and route matching, so the project
// comes from the matched path rather than an untrusted header or request body.
func Capacity(gate capacityGate) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			auth, ok := sessionhttp.GetAuthContext(r.Context())
			if !ok {
				httpx.Error(w, 401, "unauthorized", "unauthorized")
				return
			}
			release, err := gate.Acquire(r.Context(), domain.ID(auth.UserID), domain.ID(chi.URLParam(r, "id")))
			if err != nil {
				capacityError(w, err)
				return
			}
			defer release()
			next.ServeHTTP(w, r)
		})
	}
}

func capacityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidProject):
		httpx.Error(w, 400, "invalid_project", "invalid project")
	case errors.Is(err, admission.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, 429, "rate_limited", "rate limited")
	default:
		w.Header().Set("Retry-After", "1")
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
	}
}
