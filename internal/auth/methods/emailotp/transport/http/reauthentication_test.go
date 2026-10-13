package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestReauthenticationCookiesAndOwner(t *testing.T) {
	for _, scenario := range []string{"ok", "no-owner", "missing", "duplicate", "login-cookie", "foreign-fields"} {
		t.Run(scenario, func(t *testing.T) {
			f := &httpFixture{}
			h := New(f, zap.NewNop())
			body := `{"code":"12345678"}`
			if scenario == "foreign-fields" {
				body = `{"code":"12345678","userId":"attacker"}`
			}
			r := httptest.NewRequest("POST", "/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if scenario != "no-owner" {
				r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}))
			}
			name := reauthenticationCookie
			if scenario == "login-cookie" {
				name = flowCookie
			}
			if scenario != "missing" {
				r.AddCookie(&http.Cookie{Name: name, Value: strings.Repeat("A", 43)})
			}
			if scenario == "duplicate" {
				r.AddCookie(&http.Cookie{Name: name, Value: strings.Repeat("A", 43)})
			}
			w := httptest.NewRecorder()
			h.ConfirmReauthentication(w, r)
			if scenario == "ok" {
				cookies := w.Result().Cookies()
				if w.Code != 200 || f.calls != 1 || len(cookies) != 2 || cookies[0].MaxAge != -1 || cookies[1].Name != sessionhttp.SessionCookieName || !cookies[1].Secure || !cookies[1].HttpOnly || strings.Contains(w.Body.String(), strings.Repeat("A", 43)) {
					t.Fatal(w.Code, w.Body.String(), cookies)
				}
			} else if w.Code < 400 || f.calls != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatal(w.Code, f.calls, w.Body.String())
			}
		})
	}
}
