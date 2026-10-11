package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	otphttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type contractEmailOTP struct{ calls int }

func (f *contractEmailOTP) Request(context.Context, string, string) (*otpservice.RequestedCode, error) {
	f.calls++
	return &otpservice.RequestedCode{Binding: validCookieToken, ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (f *contractEmailOTP) Confirm(context.Context, otpservice.ConfirmInput) (*sessionservice.CreatedSession, error) {
	f.calls++
	return &sessionservice.CreatedSession{RawToken: validCookieToken, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestEmailOTPRoutes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, origin := range []string{"", "https://evil.test", "https://localhost:8443"} {
			for _, action := range []string{"request", "confirm"} {
				h := contractHandlers("test")
				h.Config.EmailOTP.Enabled = enabled
				f := &contractEmailOTP{}
				h.EmailOTP = otphttp.New(f, zap.NewNop())
				body := `{"email":"user@example.test"}`
				want := 202
				if action == "confirm" {
					body = `{"code":"12345678"}`
					want = 200
				}
				if origin != "https://localhost:8443" {
					want = 403
				} else if !enabled {
					want = 404
				}
				r := httptest.NewRequest("POST", "/api/v1/auth/email-otp/"+action, strings.NewReader(body))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(&http.Cookie{Name: "__Host-email-otp", Value: validCookieToken})
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || (want >= 400 && f.calls != 0) {
					t.Fatal(enabled, origin, action, w.Code, w.Body.String())
				}
			}
		}
	}
}
