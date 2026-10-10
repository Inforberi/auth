package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type sessionStub struct {
	err   error
	calls int
}

func (s *sessionStub) ValidateSession(context.Context, string) (*service.ValidateSession, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &service.ValidateSession{UserID: "user", TokenHash: "hash", Extended: true, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestAuthContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cookie bool
		status int
		body   string
	}{
		{"missing cookie", nil, false, 401, "{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}\n"},
		{"not found", domain.ErrSessionNotFound, true, 401, "{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}\n"},
		{"expired wrapped", fmt.Errorf("private: %w", domain.ErrSessionExpired), true, 401, "{\"code\":\"unauthorized\",\"message\":\"unauthorized\"}\n"},
		{"dependency failure", errors.New("secret SQL"), true, 503, "{\"code\":\"temporarily_unavailable\",\"message\":\"temporarily unavailable\"}\n"},
		{"valid and refreshed", nil, true, 204, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &sessionStub{err: tc.err}
			m := New(svc, zap.NewNop())
			r := httptest.NewRequest("POST", "/", nil)
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "token"})
			}
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				auth, ok := GetAuthContext(r.Context())
				if !ok || auth.UserID != "user" || auth.TokenHash != "hash" {
					t.Fatal("auth context lost")
				}
				w.WriteHeader(204)
			})
			w := httptest.NewRecorder()
			m.Auth(next).ServeHTTP(w, r)
			if w.Code != tc.status || w.Body.String() != tc.body || called != (tc.status == 204) {
				t.Fatal(w.Code, w.Body.String(), called)
			}
			if !tc.cookie && svc.calls != 0 {
				t.Fatal("missing cookie reached session service")
			}
			cookies := w.Result().Cookies()
			if tc.status == 204 {
				if len(cookies) != 1 || cookies[0].Value != "token" || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatal("cookie refresh changed")
				}
			} else if len(cookies) != 0 {
				t.Fatal("rejected session refreshed")
			}
		})
	}
}
