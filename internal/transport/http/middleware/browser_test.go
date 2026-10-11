package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserProtection(t *testing.T) {
	for _, tc := range []struct {
		name, method, origin, preflight, headers string
		cors, called                             bool
		status                                   int
	}{
		{"cli read", "GET", "", "", "", false, true, 200},
		{"missing mutation origin", "POST", "", "", "", false, false, 403},
		{"null", "POST", "null", "", "", true, false, 403},
		{"foreign read", "GET", "https://evil.test", "", "", true, false, 403},
		{"trusted mutation", "POST", "https://app.test", "", "", false, true, 200},
		{"credentialed read", "GET", "https://app.test", "", "", true, true, 200},
		{"disabled preflight", "OPTIONS", "https://app.test", "POST", "Content-Type", false, false, 403},
		{"json preflight", "OPTIONS", "https://app.test", "POST", "content-type", true, false, 204},
		{"get preflight", "OPTIONS", "https://app.test", "GET", "", true, false, 204},
		{"delete preflight", "OPTIONS", "https://app.test", "DELETE", "", true, false, 204},
		{"foreign preflight", "OPTIONS", "https://evil.test", "POST", "", true, false, 403},
		{"missing method", "OPTIONS", "https://app.test", "", "", true, false, 403},
		{"unsupported method", "OPTIONS", "https://app.test", "PUT", "", true, false, 403},
		{"unsupported header", "OPTIONS", "https://app.test", "POST", "Content-Type, Authorization", true, false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := BrowserProtection(OriginConfig{AllowedOrigins: []string{"https://app.test"}, CORSEnabled: tc.cors})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true }))
			r := httptest.NewRequest(tc.method, "/auth", nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.preflight != "" {
				r.Header.Set("Access-Control-Request-Method", tc.preflight)
			}
			if tc.headers != "" {
				r.Header.Set("Access-Control-Request-Headers", tc.headers)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || called != tc.called || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code, called, w.Header())
			}
			allowed := w.Header().Get("Access-Control-Allow-Origin")
			if tc.cors && tc.origin == "https://app.test" {
				if allowed != tc.origin || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Fatal("missing credentialed CORS")
				}
			} else if allowed != "" {
				t.Fatal("untrusted CORS response")
			}
		})
	}
}
