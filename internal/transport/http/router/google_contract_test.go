package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestGoogleRoutesAndCookieIsolation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, tc := range []struct {
			method, path, origin, cookie string
			want                         int
		}{
			{"POST", "/google/start", "", "", 403},
			{"POST", "/google/start", "https://evil.test", "", 403},
			{"POST", "/google/start", "https://localhost:8443", "", 200},
			{"GET", "/google/callback?code=c&state=s", "", "__Host-google-flow", 200},
			{"GET", "/google/callback?code=c&state=s", "", "__Host-telegram-flow", 400},
			{"GET", "/google/callback?code=c&code=d&state=s", "", "__Host-google-flow", 400},
			{"POST", "/google/link", "https://localhost:8443", "", 401},
			{"DELETE", "/google/link", "https://localhost:8443", "", 401},
			{"POST", "/google/link", "", "session", 403},
			{"POST", "/google/link", "https://localhost:8443", "session", 200},
			{"DELETE", "/google/link", "https://localhost:8443", "session", 204},
		} {
			h := contractHandlers("test")
			h.Config.Google.Enabled = enabled
			r := httptest.NewRequest(tc.method, "/api/v1/auth"+tc.path, nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.cookie != "" {
				name := tc.cookie
				if name == "session" {
					name = sessionhttp.SessionCookieName
				}
				r.AddCookie(&http.Cookie{Name: name, Value: validCookieToken})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			want := tc.want
			if !enabled && want != 403 {
				want = 404
			}
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(enabled, tc, w.Code, w.Body.String())
			}
			if tc.path == "/google/start" && want == 200 {
				cookies := w.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != "__Host-google-flow" || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatal("Google flow cookie not isolated", cookies)
				}
			}
			if want >= 400 && len(w.Result().Cookies()) != 0 {
				t.Fatal("error changed cookies")
			}
		}
	}
}
