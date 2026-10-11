package router

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

type contractTemporaryPassword struct {
	calls int
	err   error
}

func (s *contractTemporaryPassword) Login(context.Context, string, string, string) (*passwordservice.TemporaryLoginResult, error) {
	s.calls++
	return &passwordservice.TemporaryLoginResult{Token: "setup-only-token", ExpiresAt: time.Now().Add(time.Minute)}, s.err
}

func (s *contractTemporaryPassword) Complete(context.Context, string, string, string, string) error {
	s.calls++
	return s.err
}

func TestTemporaryPasswordHTTPContract(t *testing.T) {
	for _, action := range []string{"login", "complete"} {
		for _, tc := range []struct {
			name, method, origin, body string
			status, calls              int
			err                        error
			code                       string
		}{
			{"success", "POST", "https://localhost:8443", `{}`, 200, 1, nil, ""},
			{"GET", "GET", "https://localhost:8443", "", 405, 0, nil, ""},
			{"origin", "POST", "https://evil.example.com", `{}`, 403, 0, nil, "invalid_origin"},
			{"no origin", "POST", "", `{}`, 403, 0, nil, "invalid_origin"},
			{"bad JSON", "POST", "https://localhost:8443", `{`, 400, 0, nil, "invalid_json"},
			{"unknown field", "POST", "https://localhost:8443", `{"role":"admin"}`, 400, 0, nil, "invalid_json"},
			{"invalid authority", "POST", "https://localhost:8443", `{}`, 400, 1, passworddomain.ErrInvalidTemporaryPassword, "invalid_temporary_password"},
			{"rate", "POST", "https://localhost:8443", `{}`, 429, 1, passworddomain.ErrRecoveryLimited, "rate_limited"},
			{"login rate", "POST", "https://localhost:8443", `{}`, 429, 1, passworddomain.ErrLoginLimited, "rate_limited"},
			{"hash busy", "POST", "https://localhost:8443", `{}`, 503, 1, passworddomain.ErrHashBusy, "temporarily_unavailable"},
			{"dependency", "POST", "https://localhost:8443", `{}`, 503, 1, errors.New("sensitive SQL error"), "temporarily_unavailable"},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				s := &contractTemporaryPassword{err: tc.err}
				h := contractHandlers("test")
				h.TemporaryPassword = passwordhttp.NewTemporaryPassword(s, zap.NewNop())
				r := httptest.NewRequest(tc.method, "/api/v1/auth/temporary-password/"+action, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != tc.status || s.calls != tc.calls || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "sensitive") {
					t.Fatal(w.Code, s.calls, w.Body.String())
				}
				if tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
					t.Fatal(w.Body.String())
				}
				if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("missing no-store")
				}
				if tc.status == 429 && w.Header().Get("Retry-After") != "60" {
					t.Fatal("missing retry budget")
				}
				if tc.status == 200 && action == "login" && !strings.Contains(w.Body.String(), `"status":"password_change_required"`) {
					t.Fatal("wrong setup scope")
				}
			})
		}
		h := contractHandlers("test")
		h.TemporaryPassword = nil
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/auth/temporary-password/"+action, strings.NewReader(`{}`)))
		if w.Code != 404 {
			t.Fatal("disabled profile published")
		}
	}
}
