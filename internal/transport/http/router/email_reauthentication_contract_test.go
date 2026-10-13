package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestEmailReauthenticationRoutes(t *testing.T) {
	for _, action := range []string{"request", "confirm"} {
		for _, mode := range []string{"valid", "origin", "session", "disabled", "mfa-disabled"} {
			t.Run(action+"-"+mode, func(t *testing.T) {
				h := contractHandlers("prod")
				h.Config.EmailOTP.Enabled = false
				f := &contractEmailOTP{}
				h.EmailOTP = otphttp.New(f, zap.NewNop())
				if mode == "disabled" {
					h.Config.EmailOTP.ReauthenticationEnabled = false
				}
				if mode == "mfa-disabled" {
					h.Config.MFA.Enabled = false
				}
				body := `{"email":"user@example.test"}`
				want := 202
				if action == "confirm" {
					body = `{"code":"12345678"}`
					want = 200
				}
				r := httptest.NewRequest("POST", "https://localhost:8443/api/v1/auth/reauthenticate/email/"+action, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				r.AddCookie(&http.Cookie{Name: "__Host-email-reauthentication", Value: validCookieToken})
				if mode != "session" {
					r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
				}
				switch mode {
				case "origin":
					r.Header.Set("Origin", "https://evil.test")
					want = 403
				case "session":
					want = 401
				case "disabled", "mfa-disabled":
					want = 404
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Code, w.Body.String())
				}
				if (mode == "valid" && f.calls != 1) || (mode != "valid" && (f.calls != 0 || len(w.Result().Cookies()) != 0)) {
					t.Fatal(f.calls, w.Result().Cookies())
				}
			})
		}
	}
}
