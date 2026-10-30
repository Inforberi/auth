package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

type contractMFASettings struct{ calls int }

func (s *contractMFASettings) Read(context.Context, accessservice.Principal) (settingsdomain.MFASnapshot, error) {
	s.calls++
	return settingsdomain.MFASnapshot{Version: 1, Policy: settingsdomain.MFAPolicy{Mode: settingsdomain.MFAOptional}}, nil
}

func (s *contractMFASettings) Update(_ context.Context, input settingsservice.MFAUpdateInput) (settingsdomain.MFASnapshot, error) {
	s.calls++
	return settingsdomain.MFASnapshot{Version: 2, Policy: input.Policy}, nil
}

func TestMFASettingsRouteGuards(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		for _, mode := range []string{"valid", "origin", "session", "engine_disabled"} {
			t.Run(method+mode, func(t *testing.T) {
				h := contractHandlers("prod")
				s := &contractMFASettings{}
				sessions := &securitySessions{}
				h.Middleware = sessionhttp.New(sessions, zap.NewNop())
				h.MFASettings = settingshttp.NewMFA(s, zap.NewNop())
				h.Config.MFA.Enabled = mode != "engine_disabled"
				r := httptest.NewRequest(method, "/api/v1/admin/auth/settings/mfa", strings.NewReader(`{"expectedVersion":1,"policy":{"mode":"optional"}}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://localhost:8443")
				want := 200
				if mode == "origin" {
					r.Header.Set("Origin", "https://evil.test")
					want = 403
				}
				if mode == "session" {
					want = 401
				} else {
					r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				require.Equal(t, want, w.Code, "%s", w.Body.String())
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				require.Empty(t, w.Header().Values("Set-Cookie"))
				if want == 200 {
					require.Equal(t, 1, s.calls)
					require.Equal(t, 1, sessions.noRefresh)
					require.Zero(t, sessions.refresh)
				} else {
					require.Zero(t, s.calls)
				}
			})
		}
	}
}
