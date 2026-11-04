package tokennativehttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (h *NativeHandler) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Origin")
		if len(r.Header.Values("Origin")) != 0 || r.Method == http.MethodOptions {
			httpx.Error(w, 403, "native_transport_required", "use a cookie-free native client without Origin")
			return
		}
		if len(r.Header.Values("Cookie")) != 0 || len(r.Header.Values("Authorization")) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery {
			httpx.Error(w, 400, "ambiguous_credentials", "use native credentials in JSON only")
			return
		}
		next.ServeHTTP(w, r)
	})
}
