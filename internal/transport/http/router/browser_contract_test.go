package router

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllAuthMutationsRequireOrigin(t *testing.T) {
	for path, methods := range readAPI(t).Paths {
		if !strings.HasPrefix(path, "/api/v1/auth/") && path != "/api/v1/dev/send-mail" {
			continue
		}
		for method := range methods {
			if method == "get" {
				continue
			}
			for _, origin := range []string{"", "null", "https://evil.test"} {
				r := httptest.NewRequest(strings.ToUpper(method), path, strings.NewReader(`{}`))
				if origin != "" {
					r.Header.Set("Origin", origin)
				}
				w := httptest.NewRecorder()
				New(contractHandlers("dev")).ServeHTTP(w, r)
				if w.Code != 403 || !strings.Contains(w.Body.String(), "invalid_origin") || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
					t.Fatal(path, method, origin, w.Code, w.Body.String())
				}
			}
		}
	}
}

func TestAuthPreflightDoesNotRequireSession(t *testing.T) {
	h := contractHandlers("test")
	h.Config.Browser.CORSEnabled = true
	r := httptest.NewRequest("OPTIONS", "/api/v1/auth/change-password", nil)
	r.Header.Set("Origin", "https://localhost:8443")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()
	New(h).ServeHTTP(w, r)
	if w.Code != 204 || len(w.Result().Cookies()) != 0 || w.Header().Get("Access-Control-Allow-Origin") != "https://localhost:8443" {
		t.Fatal(w.Code, w.Header())
	}
	r = httptest.NewRequest("POST", "/api/v1/auth/change-password", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://localhost:8443")
	w = httptest.NewRecorder()
	New(h).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("CORS bypassed session authentication", w.Code)
	}
}
