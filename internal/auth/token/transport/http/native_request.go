package http

import (
	"bytes"
	"io"
	"mime"
	"net/http"

	"github.com/go-jose/go-jose/v4/json"

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

func decodeNative(w http.ResponseWriter, r *http.Request, dst any, required []string, optional ...string) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && media == "application/json" {
		data, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		var fields map[string]json.RawMessage
		if readErr == nil && json.Unmarshal(data, &fields) == nil && fields != nil {
			valid := true
			for _, key := range required {
				if fields[key] == nil {
					valid = false
				}
			}
			for _, key := range append(required, optional...) {
				if value, ok := fields[key]; ok {
					if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
						valid = false
					}
					delete(fields, key)
				}
			}
			if valid && len(fields) == 0 && json.Unmarshal(data, dst) == nil {
				return true
			}
		}
	}
	httpx.Error(w, 400, "invalid_json", "invalid JSON")
	return false
}
