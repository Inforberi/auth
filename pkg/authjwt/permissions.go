package authjwt

import (
	"net/http"
	"slices"
	"strings"
)

// RequirePermissions requires every listed permission. Object/field ownership remains the data backend's job.
func RequirePermissions(permissions ...string) (func(http.Handler) http.Handler, error) {
	keys := slices.Clone(permissions)
	slices.Sort(keys)
	if !validScope(strings.Join(keys, " ")) {
		return nil, ErrConfiguration
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				writeBearerError(w, ErrInvalidToken)
				return
			}
			for _, key := range keys {
				if !p.HasPermission(key) {
					w.Header().Set("Cache-Control", "no-store")
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="insufficient_scope", scope="`+strings.Join(keys, " ")+`"`)
					w.WriteHeader(http.StatusForbidden)
					if _, err := w.Write([]byte(`{"error":"insufficient_scope"}`)); err != nil {
						return
					}
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}
