package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type contractAccess struct {
	calls int
	err   error
}

func (s *contractAccess) PermissionCatalog(context.Context, accessservice.Principal) ([]settings.Permission, error) {
	s.calls++
	return []settings.Permission{}, s.err
}

func (s *contractAccess) ListManagedRoles(context.Context, accessservice.Principal, string, int) ([]accessdomain.Role, error) {
	s.calls++
	return []accessdomain.Role{}, s.err
}

func (s *contractAccess) ReadManagedRole(context.Context, accessservice.Principal, accessdomain.RoleID) (accessdomain.Role, error) {
	s.calls++
	return accessdomain.Role{}, s.err
}

func (s *contractAccess) CreateRole(context.Context, accessservice.CreateRoleInput) (accessdomain.Role, error) {
	s.calls++
	return accessdomain.Role{}, s.err
}

func (s *contractAccess) UpdateRole(context.Context, accessservice.UpdateRoleInput) (accessdomain.Role, error) {
	s.calls++
	return accessdomain.Role{}, s.err
}

func (s *contractAccess) ChangeAssignment(context.Context, accessservice.AssignmentInput) (int64, error) {
	s.calls++
	return 2, s.err
}

func (s *contractAccess) ChangeAdministrator(context.Context, accessservice.AdministratorInput) (int64, error) {
	s.calls++
	return 2, s.err
}

func (s *contractAccess) UserAccess(context.Context, accessservice.Principal) (accessdomain.UserAccess, error) {
	s.calls++
	return accessdomain.UserAccess{Version: 1}, s.err
}

func (s *contractAccess) AssignmentAccess(context.Context, accessservice.Principal, accountdomain.UserID) (accessdomain.UserAccess, error) {
	s.calls++
	return accessdomain.UserAccess{Version: 1}, s.err
}

func TestAccessRouteGuards(t *testing.T) {
	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/api/v1/auth/access"},
		{"GET", "/api/v1/admin/permissions"},
		{"GET", "/api/v1/admin/roles"},
		{"GET", "/api/v1/admin/roles/22222222-2222-4222-8222-222222222222"},
		{"GET", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/access"},
		{"POST", "/api/v1/admin/roles"},
		{"POST", "/api/v1/admin/roles/22222222-2222-4222-8222-222222222222"},
		{"POST", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/roles/33333333-3333-4333-8333-333333333333"},
		{"DELETE", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/roles/33333333-3333-4333-8333-333333333333"},
		{"POST", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/administrator"},
		{"DELETE", "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/administrator"},
	} {
		t.Run(endpoint.method+endpoint.path, func(t *testing.T) {
			h := contractHandlers("prod")
			svc := &contractAccess{}
			h.Access = accesshttp.New(svc, zap.NewNop())
			router := New(h)
			for _, tc := range []struct {
				cookie, origin string
				status         int
			}{
				{"", "https://localhost:8443", 401},
				{validCookieToken, "https://evil.example", 403},
				{validCookieToken, "https://localhost:8443", 200},
			} {
				before := svc.calls
				req := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(`{}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", tc.origin)
				if tc.cookie != "" {
					req.AddCookie(&http.Cookie{Name: "__Host-session", Value: tc.cookie})
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				want := tc.status
				if want == 200 && endpoint.method == "POST" && endpoint.path == "/api/v1/admin/roles" {
					want = 201
				}
				if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
					t.Fatal("route/auth/cache/cookie guard", w.Code, w.Body.String())
				}
				if (want < 300 && svc.calls != before+1) || (want >= 400 && svc.calls != before) {
					t.Fatal("unexpected service invocation")
				}
			}
		})
	}
}

func TestAccessMutationRequiresEnabledMFA(t *testing.T) {
	h := contractHandlers("prod")
	h.Config.MFA.Enabled = false
	router := New(h)
	for _, method := range []string{"POST", "DELETE"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/administrator", nil))
		if w.Code != 404 {
			t.Fatal("MFA-disabled administrator mutation exposed", w.Code)
		}
		path := "/api/v1/admin/users/22222222-2222-4222-8222-222222222222/roles/33333333-3333-4333-8333-333333333333"
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code != 404 {
			t.Fatal("MFA-disabled mutation is exposed", w.Code)
		}
	}
}
