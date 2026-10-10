package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type protectedRecoveryStub struct {
	err                               error
	calls                             int
	token, password, confirmation, ip string
}

func (s *protectedRecoveryStub) Recover(_ context.Context, token, password, confirmation, ip string) error {
	s.calls++
	s.token, s.password, s.confirmation, s.ip = token, password, confirmation, ip
	return s.err
}

func TestProtectedRecoveryHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
		err              error
		status           int
	}{
		{"success", `{"token":"proof","newPassword":"secret","confirmPassword":"secret"}`, "ok", nil, 200},
		{"format", `{"token":"proof","email":"attacker@example.com"}`, "invalid_json", nil, 400},
		{"invalid", `{}`, "invalid_account_recovery", accountdomain.ErrInvalidAccountRecovery, 400},
		{"same password", `{}`, "same_password", domain.ErrSamePassword, 400},
		{"policy", `{}`, "password_policy", domain.ErrPasswordTooShort, 400},
		{"confirmation", `{}`, "password_mismatch", domain.ErrPasswordConfirmation, 400},
		{"limits", `{}`, "rate_limited", domain.ErrRecoveryLimited, 429},
		{"dependency", `{}`, "temporarily_unavailable", errors.New("private token/password/database"), 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &protectedRecoveryStub{err: tc.err}
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Forwarded-For", "forged")
			r.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			NewProtectedRecovery(s, zap.NewNop()).Recover(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "secret") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code, w.Body.String(), w.Header())
			}
			if tc.status == 200 && (!strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") || s.token != "proof" || s.password != "secret" || s.confirmation != "secret" || s.ip != "127.0.0.1") {
				t.Fatal("wrong recovery handoff", s, w.Header())
			}
			if tc.name == "format" && s.calls != 0 {
				t.Fatal("malformed JSON reached service")
			}
		})
	}
}
