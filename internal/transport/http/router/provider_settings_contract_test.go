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

type contractProviders struct {
	calls int
	input settingsservice.ProviderUpdateInput
	err   error
}

func (s *contractProviders) Read(_ context.Context, actor accessservice.Principal, name string) (settingsdomain.ProviderSnapshot, error) {
	s.calls++
	s.input.Actor = actor
	s.input.Provider = name
	return settingsdomain.ProviderSnapshot{Provider: name, Version: 1, ClientID: "123", SecretSet: true}, s.err
}

func (s *contractProviders) Update(_ context.Context, input settingsservice.ProviderUpdateInput) (settingsdomain.ProviderSnapshot, error) {
	s.calls++
	s.input = input
	return settingsdomain.ProviderSnapshot{Provider: input.Provider, Version: 2, ClientID: input.ClientID, SecretSet: true}, s.err
}

func TestProviderSettingsContracts(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, mode := range []string{"valid", "origin", "session", "disabled", "conflict", "shape"} {
			t.Run(method+mode, func(t *testing.T) {
				s := &contractProviders{}
				h := contractHandlers("prod")
				sessions := &securitySessions{}
				h.Middleware = sessionhttp.New(sessions, zap.NewNop())
				h.ProviderSettings = settingshttp.NewProviders(s, zap.NewNop())
				if mode == "disabled" {
					h.Config.MFA.Enabled = false
				}
				if mode == "conflict" {
					s.err = settingsdomain.ErrPolicyConflict
				}
				body := `{"expectedVersion":1,"clientId":"123","clientSecret":"synthetic-secret"}`
				if mode == "shape" {
					body = `{"expectedVersion":1,"clientSecret":"private","actor":"forged"}`
				}
				r := httptest.NewRequest(method, "/api/v1/admin/auth/settings/providers/telegram", strings.NewReader(body))
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
				case mode == "disabled" && method == "POST":
					want = 405
				case mode == "conflict":
					want = 409
				case mode == "shape" && method == "POST":
					want = 400
				}
				if w.Code != want || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "synthetic-secret") || strings.Contains(w.Body.String(), "private") {
					t.Fatal(w.Code, w.Body.String())
				}
				if want == 200 && (s.calls != 1 || sessions.refresh != 0 || sessions.noRefresh != 1 || s.input.Actor.TokenHash == "" || s.input.Provider != "telegram") {
					t.Fatal("trusted principal/no refresh", s, sessions)
				}
			})
		}
	}
}
