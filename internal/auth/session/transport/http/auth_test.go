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
	err    error
	calls  int
	result *service.ValidationResult
}

const validCookieToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func (s *sessionStub) ValidateSessionWithoutRefresh(ctx context.Context, token string) (*service.ValidationResult, error) {
	return s.ValidateSession(ctx, token)
}

func (s *sessionStub) ValidateSession(context.Context, string) (*service.ValidationResult, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.result != nil {
		return s.result, nil
	}
	return &service.ValidationResult{UserID: "user", TokenHash: "hash", Extended: true, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestAuthenticationContextComesFromSession(t *testing.T) {
	verified := time.Now().UTC()
	for _, mfa := range []*time.Time{nil, &verified} {
		svc := &sessionStub{result: &service.ValidationResult{
			UserID: "user", TokenHash: "hash", AuthVersion: 7,
			PrimaryMethod: "password", PrimaryVerifiedAt: &verified, MFAVerifiedAt: mfa,
		}}
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: validCookieToken})
		r.Header.Set("X-MFA-Verified", "true")
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			auth, ok := GetAuthContext(r.Context())
			if !ok || auth.AuthVersion != 7 || auth.PrimaryMethod != "password" || auth.PrimaryVerifiedAt != &verified || auth.MFAVerifiedAt != mfa {
				t.Fatal("authentication context lost or invented")
			}
			w.WriteHeader(204)
		})
		w := httptest.NewRecorder()
		New(svc, zap.NewNop()).NoRefreshAuth(next).ServeHTTP(w, r)
		if !called || w.Code != 204 {
			t.Fatal("middleware rejected session")
		}
	}
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
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: validCookieToken})
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
				if len(cookies) != 1 || cookies[0].Value != validCookieToken || !cookies[0].Secure || !cookies[0].HttpOnly {
					t.Fatal("cookie refresh changed")
				}
			} else if len(cookies) != 0 {
				t.Fatal("rejected session refreshed")
			}
		})
	}
}
