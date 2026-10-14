package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type contractEmailBinding struct {
	calls int
	input accountservice.EmailBindingInput
	proof mfaservice.Proof
	err   error
}

func (f *contractEmailBinding) Request(_ context.Context, input accountservice.EmailBindingInput) (time.Time, error) {
	f.calls++
	f.input = input
	return time.Now().Add(time.Minute), f.err
}

func (f *contractEmailBinding) Confirm(_ context.Context, p mfaservice.Proof, _, _ string) error {
	f.calls++
	f.proof = p
	return f.err
}

func TestEmailBindingRoutes(t *testing.T) {
	for _, action := range []string{"approve", "confirm"} {
		for _, mode := range []string{"ok", "origin", "session", "disabled", "mfa-disabled", "email-proof-disabled", "error", "client-authority", "get"} {
			t.Run(action+"-"+mode, func(t *testing.T) {
				h := contractHandlers("prod")
				f := &contractEmailBinding{}
				h.EmailBinding = accounthttp.NewEmailBinding(f, zap.NewNop())
				path := "/api/v1/admin/users/00000000-0000-0000-0000-000000000002/email-binding"
				body := `{"email":"user@example.test"}`
				want := 202
				if action == "confirm" {
					path = "/api/v1/auth/email/binding/confirm"
					body = `{"code":"12345678"}`
					want = 200
				}
				method := "POST"
				switch mode {
				case "disabled":
					h.Config.EmailBinding.Enabled = false
					want = 404
				case "mfa-disabled":
					h.Config.MFA.Enabled = false
					want = 404
				case "email-proof-disabled":
					h.Config.EmailOTP.ReauthenticationEnabled = false
					want = 404
				case "origin", "error":
					want = 403
				case "session":
					want = 401
				case "client-authority":
					body = `{"email":"user@example.test","code":"12345678","actorId":"attacker","verified":true}`
					want = 400
				case "get":
					method = "GET"
					want = 405
				}
				if mode == "error" {
					f.err = accessdomain.ErrForbidden
				}
				r := httptest.NewRequest(method, "https://localhost:8443"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.test")
				}
				if mode != "session" {
					r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Code, w.Body.String())
				}
				if mode == "ok" || mode == "error" {
					if f.calls != 1 || (action == "approve" && (f.input.Actor.TokenHash == "" || f.input.UserID != "00000000-0000-0000-0000-000000000002")) || (action == "confirm" && f.proof.AuthVersion != 7) {
						t.Fatal(f)
					}
				} else if f.calls != 0 {
					t.Fatal("rejected request reached service")
				}
				if mode == "ok" && action == "confirm" {
					cookies := w.Result().Cookies()
					if len(cookies) != 1 || cookies[0].MaxAge != -1 {
						t.Fatal("owner session cookie not cleared", cookies)
					}
				} else if len(w.Result().Cookies()) != 0 {
					t.Fatal("unexpected cookie mutation")
				}
			})
		}
	}
}
