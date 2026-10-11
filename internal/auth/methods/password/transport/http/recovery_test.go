package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type recoveryService struct {
	err error
	ip  string
}

type recoveryLimiter struct{}

func (recoveryLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}

func TestForgotEmptyEmail(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	// Real service validates input; nil dependencies must not be reached afterwards.
	s := passwordservice.NewRecovery(nil, cipher, recoveryLimiter{}, nil, nil, passwordservice.Config{})
	h := NewRecovery(s, zap.NewNop())
	for _, body := range []string{`{}`, `{"email":""}`, `{"email":"   "}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.Forgot(w, r)
		if w.Code != 400 || w.Body.String() != "{\"code\":\"invalid_email\",\"message\":\"invalid email\"}\n" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func (s *recoveryService) Forgot(_ context.Context, _, ip string) error { s.ip = ip; return s.err }

func (s *recoveryService) Reset(_ context.Context, _, _, _, ip string) error { s.ip = ip; return s.err }

func TestRecoveryErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{nil, 200, "ok"},
		{domain.ErrInvalidReset, 400, "invalid_reset"},
		{domain.ErrPasswordConfirmation, 400, "password_mismatch"},
		{domain.ErrPasswordTooShort, 400, "password_policy"},
		{domain.ErrRecoveryLimited, 429, "rate_limited"},
		{errors.New("private SQL details"), 503, "temporarily_unavailable"},
	} {
		svc := &recoveryService{err: tc.err}
		h := NewRecovery(svc, zap.NewNop())
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"token":"token","newPassword":"ExamplePass2","confirmPassword":"ExamplePass2"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", "forged-ip")
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		h.Reset(w, r)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) || strings.Contains(w.Body.String(), "private") || svc.ip != "127.0.0.1" {
			t.Fatal(w.Code, w.Body.String(), svc.ip)
		}
	}
}
