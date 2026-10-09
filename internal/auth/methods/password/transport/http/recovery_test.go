package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type recoveryService struct {
	err error
	ip  string
}

func (s *recoveryService) Forgot(_ context.Context, _, ip string) error      { s.ip = ip; return s.err }
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
