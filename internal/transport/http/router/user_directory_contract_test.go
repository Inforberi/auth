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
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

type contractUserDirectory struct {
	calls  int
	err    error
	input  accountservice.UserListInput
	actor  accessservice.Principal
	target accountdomain.UserID
}

func (s *contractUserDirectory) List(_ context.Context, actor accessservice.Principal, input accountservice.UserListInput) (accountservice.UserPage, error) {
	s.calls++
	s.actor, s.input = actor, input
	return accountservice.UserPage{}, s.err
}

func (s *contractUserDirectory) Read(_ context.Context, actor accessservice.Principal, id accountdomain.UserID) (accountservice.UserDetail, error) {
	s.calls++
	s.actor, s.target = actor, id
	return accountservice.UserDetail{}, s.err
}

func TestUserDirectoryHTTPContracts(t *testing.T) {
	for _, path := range []string{"/api/v1/admin/users", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222"} {
		for _, tc := range []struct {
			name, origin string
			cookie       bool
			err          error
			status       int
			code         string
		}{
			{"success", "", true, nil, 200, ""},
			{"allowed origin", "https://localhost:8443", true, nil, 200, ""},
			{"origin", "https://evil.example", true, nil, 403, "invalid_origin"},
			{"no session", "", false, nil, 401, "unauthorized"},
			{"permission", "", true, accessdomain.ErrForbidden, 403, "forbidden"},
			{"query", "", true, accountdomain.ErrInvalidUserQuery, 400, "invalid_query"},
			{"bounds", "", true, accountdomain.ErrUserDirectoryConflict, 409, "directory_conflict"},
			{"SQL failure", "", true, errors.New("password=sensitive DSN"), 503, "temporarily_unavailable"},
		} {
			t.Run(path+tc.name, func(t *testing.T) {
				h := contractHandlers("prod")
				s := &contractUserDirectory{err: tc.err}
				h.UserDirectory = accounthttp.NewUserDirectory(s, zap.NewNop())
				h.Config.MFA.Enabled = false
				r := httptest.NewRequest("GET", path, nil)
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
				}
				if tc.cookie {
					r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
				}
				w := httptest.NewRecorder()
				New(h).ServeHTTP(w, r)
				if w.Code != tc.status || len(w.Result().Cookies()) != 0 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "sensitive") {
					t.Fatal(w.Code, w.Body.String())
				}
				if tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
					t.Fatal("error contract", w.Body.String())
				}
				if tc.err == nil && tc.status >= 400 && s.calls != 0 {
					t.Fatal("guard bypass")
				}
				if tc.status == 200 && (s.calls != 1 || s.actor.UserID != "user-1" || s.actor.TokenHash != "hash") {
					t.Fatal("principal was not authenticated")
				}
				if tc.status == 200 && path == "/api/v1/admin/users" && !strings.Contains(w.Body.String(), `"users":[]`) {
					t.Fatal("null user page")
				}
				if tc.status == 200 && path != "/api/v1/admin/users" && (!strings.Contains(w.Body.String(), `"contacts":[]`) || !strings.Contains(w.Body.String(), `"roles":[]`) || !strings.Contains(w.Body.String(), `"externalIssuers":[]`)) {
					t.Fatal("null detail arrays")
				}
			})
		}
	}
}

func TestUserDirectoryQueryShape(t *testing.T) {
	for _, query := range []string{"limit=x", "limit=1&limit=2", "email=%ZZ", "sort=name", "actor=x"} {
		h := contractHandlers("prod")
		s := &contractUserDirectory{}
		h.UserDirectory = accounthttp.NewUserDirectory(s, zap.NewNop())
		r := httptest.NewRequest("GET", "/api/v1/admin/users?"+query, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		if w.Code != 400 || s.calls != 0 {
			t.Fatal("ambiguous query reached service", query, w.Code)
		}
	}
	h := contractHandlers("prod")
	s := &contractUserDirectory{}
	h.UserDirectory = accounthttp.NewUserDirectory(s, zap.NewNop())
	r := httptest.NewRequest("GET", "/api/v1/admin/users?email=USER%40example.com&status=active&before=cursor&limit=2", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
	w := httptest.NewRecorder()
	New(h).ServeHTTP(w, r)
	if w.Code != 200 || s.input.Email != "USER@example.com" || s.input.Status != "active" || s.input.Before != "cursor" || s.input.Limit != 2 {
		t.Fatal("transport must preserve domain input", w.Code, s.input)
	}
}
