package middleware

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type OriginConfig struct {
	AllowedOrigins []string `env:"AUTH_ALLOWED_ORIGINS" env-separator:","`
}

func (cfg OriginConfig) Validate() error {
	if len(cfg.AllowedOrigins) == 0 {
		return fmt.Errorf("AUTH_ALLOWED_ORIGINS is required")
	}
	for _, origin := range cfg.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin {
			return fmt.Errorf("AUTH_ALLOWED_ORIGINS must contain exact HTTPS origins without paths")
		}
	}
	return nil
}

func RequireOrigin(cfg OriginConfig) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		allowed[origin] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 || !allowed[origins[0]] {
				w.Header().Set("Cache-Control", "no-store")
				httpx.Error(w, http.StatusForbidden, "invalid_origin", "origin not allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
