package middleware

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func BrowserProtection(cfg OriginConfig) func(http.Handler) http.Handler {
	if cfg.PolicySource != nil {
		return dynamicBrowserProtection(cfg)
	}
	return func(next http.Handler) http.Handler {
		trusted := RequireOrigin(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.CORSEnabled {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Expose-Headers", "Retry-After, X-Request-ID")
			}
			if r.Method == http.MethodOptions {
				if !cfg.CORSEnabled || !validPreflight(r) {
					httpx.Error(w, http.StatusForbidden, "invalid_preflight", "preflight not allowed")
					return
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
			}
			// Safe reads without Origin support CLI clients; mutations never have this fallback.
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && len(r.Header.Values("Origin")) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			trusted.ServeHTTP(w, r)
		})
	}
}

func validPreflight(r *http.Request) bool {
	methods := r.Header.Values("Access-Control-Request-Method")
	if len(methods) != 1 || (methods[0] != "GET" && methods[0] != "POST" && methods[0] != "DELETE") {
		return false
	}
	for _, value := range r.Header.Values("Access-Control-Request-Headers") {
		for _, name := range strings.Split(value, ",") {
			if !strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
				return false
			}
		}
	}
	return true
}

func dynamicBrowserProtection(cfg OriginConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		var mu sync.Mutex
		var current OriginConfig
		var handler http.Handler
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			policy, err := cfg.PolicySource(r.Context())
			if err != nil {
				w.Header().Set("Cache-Control", "no-store")
				httpx.Error(w, http.StatusServiceUnavailable, "temporarily_unavailable", "temporarily unavailable")
				return
			}
			mu.Lock()
			if handler == nil || policy.CORSEnabled != current.CORSEnabled || !slices.Equal(policy.AllowedOrigins, current.AllowedOrigins) {
				current = policy
				handler = BrowserProtection(policy)(next)
			}
			active := handler
			mu.Unlock()
			active.ServeHTTP(w, r)
		})
	}
}
