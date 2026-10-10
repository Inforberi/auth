package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type verificationService struct {
	err error
	ip  string
}

func (s *verificationService) AllowRegistration(_ context.Context, ip string) error {
	s.ip = ip
	return s.err
}
func (s *verificationService) Resend(_ context.Context, _, ip string) error         { s.ip = ip; return s.err }
func (s *verificationService) Confirm(_ context.Context, _, ip string) error        { s.ip = ip; return s.err }
func (s *verificationService) RequireVerified(context.Context, domain.UserID) error { return s.err }

func TestVerificationHTTP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		err     error
		status  int
		code    string
		confirm bool
	}{
		{"resend accepted", `{"email":"user@example.com"}`, nil, 202, "accepted", false},
		{"invalid email", `{"email":"bad"}`, domain.ErrEmailInvalid, 400, "invalid_email", false},
		{"missing email", `{}`, domain.ErrEmailRequired, 400, "invalid_email", false},
		{"wrapped email error", `{"email":"bad"}`, fmt.Errorf("private: %w", domain.ErrEmailInvalid), 400, "invalid_email", false},
		{"invalid JSON", `{"email":"user@example.com","unknown":true}`, nil, 400, "invalid_json", false},
		{"limited", `{"email":"user@example.com"}`, domain.ErrVerificationLimited, 429, "rate_limited", false},
		{"SQL unavailable", `{"email":"user@example.com"}`, errors.New("secret SQL details"), 503, "temporarily_unavailable", false},
		{"confirmed", `{"token":"token"}`, nil, 200, "ok", true},
		{"replayed", `{"token":"token"}`, domain.ErrInvalidVerification, 400, "invalid_verification", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &verificationService{err: tc.err}
			h := New(svc, zap.NewNop())
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "forged-ip")
			req.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			if tc.confirm {
				h.Confirm(w, req)
			} else {
				h.Resend(w, req)
			}
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal(w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatal("dependency details leaked")
			}
			if svc.ip != "" && svc.ip != "127.0.0.1" {
				t.Fatal("forwarded IP trusted")
			}
			if tc.status == 429 && w.Header().Get("Retry-After") == "" {
				t.Fatal("missing retry guidance")
			}
		})
	}
}

func TestVerifiedGate(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{domain.ErrEmailUnverified, 403}, {errors.New("SQL down"), 503}, {nil, 204},
	} {
		h := New(&verificationService{err: tc.err}, zap.NewNop())
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req = req.WithContext(sessionhttp.SetAuthContext(req.Context(), sessionhttp.Auth{UserID: "user"}))
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) })
		w := httptest.NewRecorder()
		h.RequireVerified(next).ServeHTTP(w, req)
		if w.Code != tc.status || called != (tc.err == nil) {
			t.Fatal("verification gate failed", w.Code, called)
		}
	}
}
