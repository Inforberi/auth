package http

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestPolicyErrorsAreSafe(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrMethodDisabled, 404, "method_disabled"},
		{domain.ErrRegistrationDisabled, 403, "registration_disabled"},
		{accountdomain.ErrEmailUnverified, 403, "email_not_verified"},
		{fmt.Errorf("%w: private DSN password token", domain.ErrPolicyUnavailable), 503, "temporarily_unavailable"},
	} {
		core, logs := observer.New(zap.DebugLevel)
		w := httptest.NewRecorder()
		if !RespondPolicyError(w, httptest.NewRequest("POST", "/login", nil), zap.New(core), tc.err) || w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private") || strings.Contains(fmt.Sprint(logs.All()), "private") || len(w.Result().Cookies()) != 0 {
			t.Fatal("policy error leaked private data")
		}
	}
	w := httptest.NewRecorder()
	if RespondPolicyError(w, httptest.NewRequest("POST", "/login", nil), zap.NewNop(), errors.New("unrelated")) {
		t.Fatal("policy mapper swallowed unrelated error")
	}
}

func TestSettingsLastAdministratorError(t *testing.T) {
	h := &Handler{log: zap.NewNop()}
	w := httptest.NewRecorder()
	h.respondError(w, httptest.NewRequest("POST", "/settings", nil), fmt.Errorf("private context: %w", accountdomain.ErrLastAdministrator))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "last_administrator") || strings.Contains(w.Body.String(), "private") {
		t.Fatal(w.Code, w.Body.String())
	}
}
