package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

type contractUserLifecycle struct {
	calls  int
	err    error
	actor  accessservice.Principal
	target accountdomain.UserID
}

func (s *contractUserLifecycle) ChangeStatus(_ context.Context, actor accessservice.Principal, change accountdomain.StatusChange) (accountdomain.AuthVersion, error) {
	s.calls++
	s.actor, s.target = actor, change.UserID
	return 2, s.err
}

func (s *contractUserLifecycle) Delete(_ context.Context, actor accessservice.Principal, deletion accountdomain.AccountDeletion) (accountdomain.AuthVersion, error) {
	s.calls++
	s.actor, s.target = actor, deletion.UserID
	return 2, s.err
}

func TestUserLifecycleHTTP(t *testing.T) {
	for _, endpoint := range []struct{ method, path, body string }{
		{"POST", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/status", `{"status":"blocked","expectedAuthVersion":1}`},
		{"DELETE", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222", `{"expectedAuthVersion":1}`},
	} {
		for _, tc := range []struct {
			name, origin string
			cookie       bool
			err          error
			status       int
			code         string
		}{
			{"success", "https://localhost:8443", true, nil, 200, ""},
			{"missing origin", "", true, nil, 403, "invalid_origin"},
			{"foreign origin", "https://evil.example", true, nil, 403, "invalid_origin"},
			{"no session", "https://localhost:8443", false, nil, 401, "unauthorized"},
			{"permission", "https://localhost:8443", true, accessdomain.ErrForbidden, 403, "forbidden"},
			{"proof", "https://localhost:8443", true, accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required"},
			{"version", "https://localhost:8443", true, accountdomain.ErrAccountConflict, 409, "account_conflict"},
			{"last admin", "https://localhost:8443", true, accountdomain.ErrLastAdministrator, 409, "last_administrator"},
			{"unknown", "https://localhost:8443", true, accountdomain.ErrAccountNotFound, 404, "user_not_found"},
			{"deleted", "https://localhost:8443", true, accountdomain.ErrAccountDeleted, 409, "account_deleted"},
			{"dependency", "https://localhost:8443", true, errors.New("private database detail"), 503, "temporarily_unavailable"},
		} {
			t.Run(endpoint.method+"/"+tc.name, func(t *testing.T) {
				s := &contractUserLifecycle{err: tc.err}
				h := contractHandlers("prod")
				h.UserLifecycle = accounthttp.NewUserLifecycle(s, zap.NewNop())
				req := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body))
				req.Header.Set("Content-Type", "application/json")
				if tc.origin != "" {
					req.Header.Set("Origin", tc.origin)
				}
				if tc.cookie {
					req.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, req)
				if w.Code != tc.status || tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
					t.Fatal(w.Code, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "private database detail") {
					t.Fatal("unsafe response", w.Header(), w.Body.String())
				}
				if tc.origin == "https://localhost:8443" && tc.cookie {
					if s.calls != 1 || s.actor.UserID == "" || s.actor.TokenHash == "" || s.target != "22222222-2222-4222-8222-222222222222" {
						t.Fatal("session actor/target lost")
					}
				} else if s.calls != 0 {
					t.Fatal("guard bypass")
				}
			})
		}
		for _, body := range []string{`{`, `{"actorId":"forged","expectedAuthVersion":1}`, `{"expectedAuthVersion":"1"}`} {
			s := &contractUserLifecycle{}
			h := contractHandlers("prod")
			h.UserLifecycle = accounthttp.NewUserLifecycle(s, zap.NewNop())
			r := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(body))
			r.Header.Set("Origin", "https://localhost:8443")
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != 400 || s.calls != 0 {
				t.Fatal("invalid DTO reached service", w.Code, w.Body.String())
			}
		}
		h := contractHandlers("prod")
		h.UserLifecycle = accounthttp.NewUserLifecycle(&contractUserLifecycle{}, zap.NewNop())
		h.Config.MFA.Enabled = false
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, httptest.NewRequest(endpoint.method, endpoint.path, nil))
		if w.Code != 404 && w.Code != 405 {
			t.Fatal("MFA-disabled mutation published", w.Code)
		}
	}
}
