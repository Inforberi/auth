package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdministrativeLoginRouteProtection(t *testing.T) {
	for _, mode := range []string{"enabled", "disabled", "missing-mfa", "origin", "request-intent"} {
		t.Run(mode, func(t *testing.T) {
			h := contractHandlers("prod")
			want := http.StatusBadRequest
			body := `{"email":"admin@example.test","password":"ExamplePass1"}`
			switch mode {
			case "disabled":
				h.Config.MFA.Enabled = false
				want = http.StatusNotFound
			case "missing-mfa":
				h.MFA = nil
				want = http.StatusNotFound
			case "origin":
				want = http.StatusForbidden
			case "request-intent":
				body = `{"email":"admin@example.test","password":"ExamplePass1","administrative":false}`
			}
			r := httptest.NewRequest("POST", "https://localhost:8443/api/v1/admin/auth/login/email", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if mode != "origin" {
				r.Header.Set("Origin", "https://localhost:8443")
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != want || len(w.Result().Cookies()) != 0 {
				t.Fatal("route protection", w.Code, w.Body.String())
			}
			if mode == "request-intent" && !strings.Contains(w.Body.String(), "invalid_json") {
				t.Fatal("client intent accepted")
			}
		})
	}
}
