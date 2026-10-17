package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

type contractRetention struct {
	calls int
	input settingsservice.RetentionUpdateInput
	err   error
}

func (s *contractRetention) Read(_ context.Context, actor accessservice.Principal) (settingsdomain.RetentionSnapshot, error) {
	s.calls++
	s.input.Actor = actor
	return settingsdomain.RetentionSnapshot{Version: 1}, s.err
}

func (s *contractRetention) Update(_ context.Context, input settingsservice.RetentionUpdateInput) (settingsdomain.RetentionSnapshot, error) {
	s.calls++
	s.input = input
	return settingsdomain.RetentionSnapshot{Version: 2, Policy: input.Policy}, s.err
}

func TestRetentionSettingsContracts(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, mode := range []string{"valid", "origin", "session", "disabled", "conflict", "shortening", "forbidden", "invalid", "unavailable", "shape", "missing"} {
			t.Run(method+mode, func(t *testing.T) {
				s := &contractRetention{}
				h := contractHandlers("prod")
				sessions := &securitySessions{}
				h.Middleware = sessionhttp.New(sessions, zap.NewNop())
				h.RetentionSettings = settingshttp.NewRetention(s, zap.NewNop())
				body := `{"expectedVersion":1,"policy":{"emailReservationDays":30,"sessionDays":30,"securityAuditDays":180},"confirmShortening":true}`
				want := 200
				switch mode {
				case "origin":
					want = 403
				case "session":
					want = 401
				case "disabled":
					h.Config.MFA.Enabled = false
					if method == "POST" {
						want = 405
					}
				case "conflict":
					s.err = settingsdomain.ErrPolicyConflict
					want = 409
				case "shortening":
					s.err = settingsdomain.ErrRetentionConfirmation
					want = 409
				case "forbidden":
					s.err = accessdomain.ErrForbidden
					want = 403
				case "invalid":
					s.err = settingsdomain.ErrInvalidRetention
					want = 400
				case "unavailable":
					s.err = context.DeadlineExceeded
					want = 503
				case "shape":
					body = `{"actor":"forged","expectedVersion":1,"policy":{}}`
					if method == "POST" {
						want = 400
					}
				case "missing":
					body = `{"expectedVersion":1}`
					if method == "POST" {
						want = 400
					}
				}
				r := httptest.NewRequest(method, "/api/v1/admin/auth/settings/retention", strings.NewReader(body))
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
				if w.Code != want || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Code, w.Body.String(), w.Header())
				}
				if want == 200 && (s.calls != 1 || sessions.refresh != 0 || sessions.noRefresh != 1 || s.input.Actor.TokenHash == "") {
					t.Fatal("trusted actor/no refresh", s, sessions)
				}
				if want == 200 && method == "POST" && (!s.input.ConfirmShortening || s.input.Policy.SecurityAuditDays != 180) {
					t.Fatal("lost request fields", s.input)
				}
			})
		}
	}
}
