package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type accountFault struct{ err error }

func (f accountFault) AllowRegistration(context.Context, string) error             { return f.err }
func (f accountFault) Resend(context.Context, string, string) error                { return f.err }
func (f accountFault) Confirm(context.Context, string, string) error               { return f.err }
func (f accountFault) RequireVerified(context.Context, accountdomain.UserID) error { return f.err }

type recoveryFault struct{ err error }

func (f recoveryFault) Forgot(context.Context, string, string) error                { return f.err }
func (f recoveryFault) Reset(context.Context, string, string, string, string) error { return f.err }

type sessionFault struct{ err error }

func (f sessionFault) ValidateSessionWithoutRefresh(ctx context.Context, token string) (*sessionservice.ValidationResult, error) {
	return f.ValidateSession(ctx, token)
}

func (f sessionFault) ValidateSession(context.Context, string) (*sessionservice.ValidationResult, error) {
	return nil, f.err
}

type passwordFault struct{ err error }

func (f passwordFault) LoginAdministrator(context.Context, passwordservice.LoginInput) (*passwordservice.LoginResult, error) {
	return nil, f.err
}

func (f passwordFault) Register(context.Context, string, string, string, string) (*passwordservice.RegisterResult, error) {
	return nil, f.err
}

func (f passwordFault) Login(context.Context, passwordservice.LoginInput) (*passwordservice.LoginResult, error) {
	return nil, f.err
}

func (f passwordFault) ChangePassword(context.Context, accountdomain.UserID, string, string, string) error {
	return f.err
}

func TestRouterErrorContracts(t *testing.T) {
	private := errors.New("secret DSN token and provider details")
	const passwordBody = `{"email":"user@example.com","password":"ExamplePass1"}`
	const resetBody = `{"token":"token","newPassword":"ExamplePass2","confirmPassword":"ExamplePass2"}`
	const changeBody = `{"oldPassword":"ExamplePass1","newPassword":"ExamplePass2","confirmPassword":"ExamplePass2"}`
	for _, tc := range []struct {
		feature, path, body, token string
		err                        error
		status                     int
		code, message, retry       string
	}{
		{"account", "email/resend", `{"email":"user@example.com"}`, "", accountdomain.ErrVerificationLimited, 429, "rate_limited", "rate limited", "60"},
		{"account", "email/verify", `{"token":"token"}`, "", accountdomain.ErrInvalidVerification, 400, "invalid_verification", "invalid verification", ""},
		{"account", "email/verify", `{"token":"token"}`, "", private, 503, "temporarily_unavailable", "temporarily unavailable", ""},
		{"account", "register/email", passwordBody, "", accountdomain.ErrVerificationLimited, 429, "rate_limited", "rate limited", "60"},
		{"account", "change-password", changeBody, "valid", accountdomain.ErrEmailUnverified, 403, "email_not_verified", "email not verified", ""},
		{"recovery", "forgot-password", `{"email":"bad"}`, "", accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email", ""},
		{"recovery", "forgot-password", `{"email":"user@example.com"}`, "", passworddomain.ErrRecoveryLimited, 429, "rate_limited", "rate limited", "900"},
		{"recovery", "reset-password", resetBody, "", passworddomain.ErrInvalidReset, 400, "invalid_reset", "invalid reset", ""},
		{"recovery", "reset-password", resetBody, "", passworddomain.ErrPasswordTooShort, 400, "password_policy", "invalid password", ""},
		{"recovery", "reset-password", resetBody, "", private, 503, "temporarily_unavailable", "temporarily unavailable", ""},
		{"password", "register/email", passwordBody, "", passworddomain.ErrPasswordTooShort, 400, "password_too_short", "password too short", ""},
		{"password", "register/email", passwordBody, "", passworddomain.ErrEmailAlreadyExists, 409, "email_already_exists", "email already exists", ""},
		{"password", "register/email", passwordBody, "", private, 500, "internal_error", "internal error", ""},
		{"password", "login/email", passwordBody, "", passworddomain.ErrInvalidEmailOrPassword, 400, "invalid_credentials", "invalid email or password", ""},
		{"password", "login/email", passwordBody, "", settingsdomain.ErrMethodDisabled, 404, "method_disabled", "login method disabled", ""},
		{"password", "register/email", passwordBody, "", settingsdomain.ErrRegistrationDisabled, 403, "registration_disabled", "public registration disabled", ""},
		{"password", "login/email", passwordBody, "", accountdomain.ErrEmailUnverified, 403, "email_not_verified", "email not verified", ""},
		{"password", "login/email", passwordBody, "", settingsdomain.ErrPolicyUnavailable, 503, "temporarily_unavailable", "temporarily unavailable", ""},
		{"password", "login/email", passwordBody, "", private, 500, "internal_error", "internal error", ""},
		{"password", "login/email", passwordBody, "", passworddomain.ErrLoginLimited, 429, "rate_limited", "rate limited", "60"},
		{"password", "login/email", passwordBody, "", passworddomain.ErrLoginUnavailable, 503, "temporarily_unavailable", "temporarily unavailable", ""},
		{"password", "login/email", passwordBody, "", passworddomain.ErrHashBusy, 503, "temporarily_unavailable", "temporarily unavailable", ""},
		{"password", "change-password", changeBody, "valid", passworddomain.ErrPasswordTooShort, 400, "password_policy", "invalid password", ""},
		{"password", "change-password", changeBody, "valid", passworddomain.ErrNotFound, 404, "not_found", "not found", ""},
		{"password", "change-password", changeBody, "valid", private, 500, "internal_error", "internal error", ""},
		{"session", "change-password", changeBody, "valid", sessiondomain.ErrSessionExpired, 401, "unauthorized", "unauthorized", ""},
		{"session", "change-password", changeBody, "valid", private, 503, "temporarily_unavailable", "temporarily unavailable", ""},
	} {
		t.Run(tc.feature+"/"+tc.path+"/"+tc.code, func(t *testing.T) {
			h := contractHandlers("test")
			err := fmt.Errorf("private wrapper: %w", tc.err)
			log := zap.NewNop()
			switch tc.feature {
			case "account":
				h.Account = accounthttp.New(accountFault{err}, log)
			case "recovery":
				h.Recovery = passwordhttp.NewRecovery(recoveryFault{err}, log)
			case "password":
				h.PasswordHandler = passwordhttp.New(passwordFault{err}, log)
			case "session":
				h.Middleware = sessionhttp.New(sessionFault{err}, log)
			}
			r := httptest.NewRequest("POST", "/api/v1/auth/"+tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://localhost:8443")
			if tc.token != "" {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: contractCookie(tc.token)})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			var response httpx.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || response.Code != tc.code || response.Message != tc.message || w.Header().Get("Retry-After") != tc.retry {
				t.Fatal(w.Code, response, w.Header())
			}
			if w.Header().Get("Content-Type") != "application/json" || len(w.Result().Cookies()) != 0 {
				t.Fatal("error response contract changed")
			}
		})
	}
}
