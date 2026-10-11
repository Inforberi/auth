package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type reauthenticationContract struct {
	calls int
	err   error
}

func (s *reauthenticationContract) Confirm(_ context.Context, user accountdomain.UserID, hash, password, _ string) (*passwordservice.ReauthenticationResult, error) {
	s.calls++
	if user != "user-1" || hash != "hash" || password != "current-password" {
		panic("wrong reauthentication input")
	}
	return &passwordservice.ReauthenticationResult{Token: strings.Repeat("B", 42) + "A", ExpiresAt: time.Now().Add(time.Hour), ValidUntil: time.Now().Add(5 * time.Minute)}, s.err
}

func TestReauthenticationHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, method, origin, body string
		cookie                     bool
		err                        error
		status, calls              int
	}{
		{"success", "POST", "https://localhost:8443", `{"password":"current-password"}`, true, nil, 200, 1},
		{"missing origin", "POST", "", `{"password":"current-password"}`, true, nil, 403, 0},
		{"wrong origin", "POST", "https://attacker.example", `{"password":"current-password"}`, true, nil, 403, 0},
		{"missing session", "POST", "https://localhost:8443", `{"password":"current-password"}`, false, nil, 401, 0},
		{"invalid JSON", "POST", "https://localhost:8443", `{`, true, nil, 400, 0},
		{"unknown field", "POST", "https://localhost:8443", `{"password":"current-password","admin":true}`, true, nil, 400, 0},
		{"wrong password", "POST", "https://localhost:8443", `{"password":"current-password"}`, true, accountdomain.ErrFreshAuthRequired, 401, 1},
		{"revoked", "POST", "https://localhost:8443", `{"password":"current-password"}`, true, sessiondomain.ErrSessionNotFound, 401, 1},
		{"rate limited", "POST", "https://localhost:8443", `{"password":"current-password"}`, true, passworddomain.ErrLoginLimited, 429, 1},
		{"dependency failed", "POST", "https://localhost:8443", `{"password":"current-password"}`, true, errors.New("secret SQL"), 503, 1},
		{"GET", "GET", "https://localhost:8443", ``, true, nil, 405, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &reauthenticationContract{err: tc.err}
			h := contractHandlers("prod")
			h.Reauthentication = passwordhttp.NewReauthentication(s, zap.NewNop())
			r := httptest.NewRequest(tc.method, "/api/v1/auth/reauthenticate/password", strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", "application/json")
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != tc.status || s.calls != tc.calls || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "current-password") {
				t.Fatal(w.Code, w.Body.String(), s.calls)
			}
			cookies := w.Result().Cookies()
			if tc.status == 200 {
				if len(cookies) != 1 || cookies[0].Value == validCookieToken || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || !strings.Contains(w.Body.String(), "validUntil") || strings.Contains(w.Body.String(), cookies[0].Value) {
					t.Fatal("cookie-only token contract", cookies, w.Body.String())
				}
			} else if len(cookies) != 0 {
				t.Fatal("failed confirmation changed cookie")
			}
			if tc.status == 429 && w.Header().Get("Retry-After") != "60" {
				t.Fatal("missing retry delay")
			}
			if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cached authentication proof")
			}
		})
	}
}
