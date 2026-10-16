package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

// These routes authenticate a primary/challenge/operator proof, not an existing session.
var sessionlessAPIRoutes = map[string]string{
	"/api/v1/setup/start": "POST", "/api/v1/setup/complete": "POST",
	"/api/v1/auth/register/email": "POST", "/api/v1/auth/login/email": "POST",
	"/api/v1/admin/auth/login/email": "POST",
	"/api/v1/auth/forgot-password":   "POST", "/api/v1/auth/reset-password": "POST",
	"/api/v1/auth/invitations/activate": "POST",
	"/api/v1/auth/email/resend":         "POST", "/api/v1/auth/email/verify": "POST",
	"/api/v1/auth/temporary-password/login": "POST", "/api/v1/auth/temporary-password/complete": "POST",
	"/api/v1/auth/google/start": "POST", "/api/v1/auth/google/callback": "GET",
	"/api/v1/auth/telegram/start": "POST", "/api/v1/auth/telegram/callback": "GET",
	"/api/v1/auth/email-otp/request": "POST", "/api/v1/auth/email-otp/confirm": "POST",
	"/api/v1/auth/mfa/login/complete": "POST",
	"/api/v1/auth/mfa/recovery/start": "POST", "/api/v1/auth/mfa/recovery/complete": "POST",
	"/api/v1/auth/email/change/confirm": "POST", "/api/v1/auth/email/change/report": "POST",
	"/api/v1/auth/email/change/recover": "POST",
}

type securitySessions struct {
	refresh, noRefresh int
	err                error
}

func (s *securitySessions) ValidateSession(ctx context.Context, token string) (*sessionservice.ValidationResult, error) {
	s.refresh++
	return s.result(ctx, token)
}

func (s *securitySessions) ValidateSessionWithoutRefresh(ctx context.Context, token string) (*sessionservice.ValidationResult, error) {
	s.noRefresh++
	return s.result(ctx, token)
}

func (s *securitySessions) result(ctx context.Context, token string) (*sessionservice.ValidationResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	result, err := (contractSessions{}).ValidateSession(ctx, token)
	if result != nil {
		result.Extended = true
		result.ExpiresAt = time.Now().Add(time.Hour)
	}
	return result, err
}

func TestProtectedAPIRoutesRequireLiveUnambiguousSession(t *testing.T) {
	h := contractHandlers("prod")
	svc := &securitySessions{err: errors.New("private SQL failure")}
	h.Middleware = sessionhttp.New(svc, zap.NewNop())
	router := New(h)
	protected := 0
	err := chi.Walk(router, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(path, "/api/v1/") || sessionlessAPIRoutes[path] == method {
			return nil
		}
		protected++
		for _, tc := range []struct {
			name, origin, cookie string
			status, calls        int
		}{
			{"missing", "https://localhost:8443", "", 401, 0},
			{"hostile origin", "https://evil.test", "__Host-session=" + validCookieToken, 403, 0},
			{"duplicate", "https://localhost:8443", "__Host-session=" + validCookieToken + "; __Host-session=" + validCookieToken, 401, 0},
			{"SQL failure", "https://localhost:8443", "__Host-session=" + validCookieToken, 503, 1},
		} {
			t.Run(method+path+"/"+tc.name, func(t *testing.T) {
				svc.refresh, svc.noRefresh = 0, 0
				req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", tc.origin)
				if tc.cookie != "" {
					req.Header.Set("Cookie", tc.cookie)
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != tc.status || svc.refresh+svc.noRefresh != tc.calls || strings.Contains(w.Body.String(), "private") || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("session/Origin/fail-closed boundary", w.Code, w.Body.String(), svc.refresh, svc.noRefresh)
				}
				if tc.calls == 1 && method != "GET" && svc.refresh != 0 {
					t.Fatal("mutation refreshes before authorization")
				}
			})
		}
		return nil
	})
	if err != nil || protected == 0 {
		t.Fatal("protected route inventory empty", err)
	}
}

func TestLifecycleMutationsDoNotEmitOldRefreshCookie(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		status             int
		clear              bool
	}{
		{"POST", "/api/v1/auth/logout-all", `{}`, 204, true},
		{"POST", "/api/v1/auth/logout", `{}`, 204, true},
		{"DELETE", "/api/v1/auth/sessions/22222222-2222-4222-8222-222222222222", `{}`, 204, false},
		{"POST", "/api/v1/auth/change-password", `{`, 400, false},
		{"POST", "/api/v1/auth/email/change", `{`, 400, false},
	} {
		svc := &securitySessions{}
		h := contractHandlers("prod")
		h.Middleware = sessionhttp.New(svc, zap.NewNop())
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Origin", "https://localhost:8443")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, req)
		if w.Code != tc.status || svc.refresh != 0 || svc.noRefresh != 1 {
			t.Fatal(tc.path, w.Code, w.Body.String(), svc.refresh, svc.noRefresh)
		}
		cookies := w.Result().Cookies()
		if tc.clear {
			if len(cookies) != 1 || cookies[0].MaxAge != -1 {
				t.Fatal("old refresh emitted before cleanup", tc.path, cookies)
			}
		} else if len(cookies) != 0 {
			t.Fatal("unexpected refresh cookie", tc.path, cookies)
		}
	}
}
