package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type RuntimeResolver interface {
	ResolveRuntime(context.Context, string) (projectruntime.Key, error)
}

type runtimeSelectionKey struct{}

type RuntimeSelection struct {
	key    projectruntime.Key
	origin string
}

func (s RuntimeSelection) Key() projectruntime.Key { return s.key }
func (s RuntimeSelection) Origin() string          { return s.origin }
func RuntimeFromContext(ctx context.Context) (RuntimeSelection, bool) {
	selected, ok := ctx.Value(runtimeSelectionKey{}).(RuntimeSelection)
	return selected, ok
}

// NewRuntimeBoundary selects a project; the caller still owns route readiness, authentication and admission.
func NewRuntimeBoundary(platformOrigin string, resolver RuntimeResolver, next http.Handler) (http.Handler, error) {
	if !domain.ValidOrigin(platformOrigin) || resolver == nil || next == nil {
		return nil, domain.ErrInvalidProject
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		origin := "https://" + r.Host
		if r.TLS == nil || origin == platformOrigin || r.URL == nil || r.URL.Opaque != "" || r.URL.Host != "" && r.URL.Host != r.Host || r.URL.Scheme != "" && r.URL.Scheme != "https" {
			http.NotFound(w, r)
			return
		}
		selected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveRuntime(w, r, origin, resolver, next) })
		if len(r.Header.Values("Origin")) > 0 {
			middleware.RequireOrigin(middleware.OriginConfig{AllowedOrigins: []string{origin}})(selected).ServeHTTP(w, r)
			return
		}
		selected.ServeHTTP(w, r)
	}), nil
}

func serveRuntime(w http.ResponseWriter, r *http.Request, origin string, resolver RuntimeResolver, next http.Handler) {
	if r.Context().Err() != nil {
		runtimeUnavailable(w)
		return
	}
	lookup, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	key, err := resolver.ResolveRuntime(lookup, origin)
	cancel()
	if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrInvalidProject) || errors.Is(err, domain.ErrConflict) {
		http.NotFound(w, r)
		return
	}
	if err != nil || r.Context().Err() != nil {
		runtimeUnavailable(w)
		return
	}
	if !key.Valid() {
		runtimeUnavailable(w)
		return
	}
	ctx := context.WithValue(r.Context(), runtimeSelectionKey{}, RuntimeSelection{key: key, origin: origin})
	next.ServeHTTP(w, r.WithContext(ctx))
}

func runtimeUnavailable(w http.ResponseWriter) {
	httpx.Error(w, http.StatusServiceUnavailable, "temporarily_unavailable", "temporarily unavailable")
}
