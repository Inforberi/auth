package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmailChangeRoutes(t *testing.T) {
	for _, path := range []string{"/api/v1/auth/email/change", "/api/v1/auth/email/change/confirm", "/api/v1/auth/email/change/report"} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range []struct {
				method, origin, cookie string
				want                   int
			}{
				{"GET", "https://localhost:8443", "valid", 405},
				{"POST", "", "valid", 403},
				{"POST", "https://attacker.example.com", "valid", 403},
				{"POST", "https://localhost:8443", "valid", 200},
			} {
				r := httptest.NewRequest(tc.method, path, strings.NewReader(`{"token":"token"}`))
				if path == "/api/v1/auth/email/change" {
					r = httptest.NewRequest(tc.method, path, strings.NewReader(`{"email":"new@example.com","password":"current"}`))
				}
				r.Header.Set("Content-Type", "application/json")
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
				}
				r.AddCookie(&http.Cookie{Name: "__Host-session", Value: tc.cookie})
				w := httptest.NewRecorder()
				New(contractHandlers("test")).ServeHTTP(w, r)
				want := tc.want
				if path == "/api/v1/auth/email/change" && want == 200 {
					want = 202
				}
				if w.Code != want {
					t.Fatal(tc, w.Code, w.Body.String())
				}
				if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store")
				}
			}
			h := contractHandlers("test")
			h.EmailChange = nil
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
			if w.Code != 404 {
				t.Fatal("disabled route exposed", w.Code)
			}
		})
	}
	h := contractHandlers("test")
	for _, path := range []string{"/api/v1/auth/email/change/confirm", "/api/v1/auth/email/change/report"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"token":"token"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://localhost:8443")
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("token operation requires compromised session", w.Code)
		}
	}
}
