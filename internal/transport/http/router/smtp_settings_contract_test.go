package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

type contractSMTP struct {
	calls int
	input settingsservice.SMTPUpdateInput
	err   error
}

func (s *contractSMTP) Read(_ context.Context, actor accessservice.Principal) (settingsdomain.SMTPSnapshot, error) {
	s.calls++
	s.input.Actor = actor
	return settingsdomain.SMTPSnapshot{Version: 1, PasswordSet: true}, s.err
}

func (s *contractSMTP) Update(_ context.Context, input settingsservice.SMTPUpdateInput) (settingsdomain.SMTPSnapshot, error) {
	s.calls++
	s.input = input
	return settingsdomain.SMTPSnapshot{Version: 2, Config: input.Config, PasswordSet: true}, s.err
}

func (s *contractSMTP) TestConnection(_ context.Context, actor accessservice.Principal, version int64) error {
	s.calls++
	s.input.Actor, s.input.ExpectedVersion = actor, version
	return s.err
}

const smtpUpdateBody = `{"expectedVersion":1,"config":{"host":"smtp.example.com","port":587,"username":"owner","from":"auth@example.com","domain":"example.com","requireTls":true},"password":"synthetic-secret"}`

func TestSMTPSettingsRoutes(t *testing.T) {
	for _, operation := range []string{"read", "update", "test"} {
		for _, mode := range []string{"valid", "origin", "session", "disabled", "conflict", "malformed"} {
			t.Run(operation+"-"+mode, func(t *testing.T) {
				s := &contractSMTP{}
				h := contractHandlers("prod")
				sessions := &securitySessions{}
				h.Middleware = sessionhttp.New(sessions, zap.NewNop())
				h.SMTPSettings = settingshttp.NewSMTP(s, zap.NewNop())
				method, path, body := "POST", "/api/v1/admin/auth/settings/smtp", smtpUpdateBody
				if operation == "read" {
					method, body = "GET", ""
				}
				if operation == "test" {
					path += "/test"
					body = `{"expectedVersion":1}`
				}
				if mode == "disabled" {
					h.Config.MFA.Enabled = false
				}
				if mode == "conflict" {
					s.err = settingsdomain.ErrPolicyConflict
				}
				if mode == "malformed" && operation != "read" {
					body = `{"password":"private","actor":"forged"}`
				}
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.Header.Set("Origin", "https://localhost:8443")
				r.Header.Set("Content-Type", "application/json")
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.test")
				}
				if mode != "session" {
					r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				want := 200
				switch {
				case mode == "origin":
					want = 403
				case mode == "session":
					want = 401
				case mode == "disabled" && operation != "read":
					if operation == "update" {
						want = 405
					} else {
						want = 404
					}
				case mode == "conflict":
					want = 409
				case mode == "malformed" && operation != "read":
					want = 400
				}
				if w.Code != want || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "synthetic-secret") || strings.Contains(w.Body.String(), "private") {
					t.Fatal(w.Code, w.Body.String(), w.Header())
				}
				if want == 200 && (s.calls != 1 || s.input.Actor.TokenHash == "" || sessions.noRefresh != 1 || sessions.refresh != 0 || w.Header().Get("Cache-Control") != "no-store") {
					t.Fatal("authority/no-refresh contract", s, sessions, w.Header())
				}
				if want == 200 && operation == "update" && (s.input.Password == nil || *s.input.Password != "synthetic-secret") {
					t.Fatal("write-only password lost")
				}
			})
		}
	}
}

func TestSMTPPasswordIntent(t *testing.T) {
	for _, value := range []string{"null", `""`, `"replacement"`} {
		s := &contractSMTP{}
		h := contractHandlers("prod")
		h.SMTPSettings = settingshttp.NewSMTP(s, zap.NewNop())
		body := strings.Replace(smtpUpdateBody, `"synthetic-secret"`, value, 1)
		r := httptest.NewRequest("POST", "/api/v1/admin/auth/settings/smtp", strings.NewReader(body))
		r.Header.Set("Origin", "https://localhost:8443")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		if w.Code != 200 || (s.input.Password == nil) != (value == "null") {
			t.Fatal("password intent lost", w.Code, value)
		}
		if s.input.Password != nil && `"`+*s.input.Password+`"` != value {
			t.Fatal("password was replaced by a mask")
		}
	}
}
