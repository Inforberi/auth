package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type captureService struct {
	accessService
	create        service.CreateRoleInput
	update        service.UpdateRoleInput
	assignment    service.AssignmentInput
	administrator service.AdministratorInput
	calls         int
	err           error
	after         string
	limit         int
}

func (s *captureService) ChangeAdministrator(_ context.Context, input service.AdministratorInput) (int64, error) {
	s.calls++
	s.administrator = input
	return 2, s.err
}

func TestAdministratorTransport(t *testing.T) {
	svc := &captureService{}
	h := New(svc, zap.NewNop())
	mux := chi.NewRouter()
	mux.Post("/users/{id}/administrator", h.GrantAdministrator)
	mux.Delete("/users/{id}/administrator", h.RevokeAdministrator)
	for _, method := range []string{"POST", "DELETE"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, accessRequest(method, "/users/33333333-3333-4333-8333-333333333333/administrator", `{"expectedAuthVersion":3,"expectedAccessVersion":4,"expectedRoleVersion":5}`))
		input := svc.administrator
		if w.Code != 200 || input.Actor != testActor || input.UserID != "33333333-3333-4333-8333-333333333333" || input.ExpectedAuthVersion != 3 || input.ExpectedAccessVersion != 4 || input.ExpectedRoleVersion != 5 || input.Grant != (method == "POST") {
			t.Fatal(w.Code, input)
		}
		for _, body := range []string{`{`, `{"actorId":"forged"}`, `{"expectedAuthVersion":"1"}`, `{"grant":true}`} {
			before := svc.calls
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, accessRequest(method, "/users/33333333-3333-4333-8333-333333333333/administrator", body))
			if w.Code != 400 || svc.calls != before {
				t.Fatal("invalid JSON reached service", w.Code)
			}
		}
	}
}

func (s *captureService) CreateRole(_ context.Context, input service.CreateRoleInput) (domain.Role, error) {
	s.calls++
	s.create = input
	return domain.Role{ID: testRole, Key: input.Key, Version: 1, Permissions: input.Permissions}, s.err
}

func (s *captureService) UpdateRole(_ context.Context, input service.UpdateRoleInput) (domain.Role, error) {
	s.calls++
	s.update = input
	return domain.Role{ID: input.RoleID, Version: 2}, s.err
}

func (s *captureService) ChangeAssignment(_ context.Context, input service.AssignmentInput) (int64, error) {
	s.calls++
	s.assignment = input
	return 2, s.err
}

func (s *captureService) ListManagedRoles(_ context.Context, _ service.Principal, after string, limit int) ([]domain.Role, error) {
	s.calls++
	s.after, s.limit = after, limit
	return []domain.Role{{ID: testRole, Key: "reader", Version: 1}}, s.err
}

const testRole domain.RoleID = "22222222-2222-4222-8222-222222222222"

var testActor = service.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}

func accessRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: testActor.UserID, TokenHash: testActor.TokenHash}))
}

func TestMutationContracts(t *testing.T) {
	svc := &captureService{}
	h := New(svc, zap.NewNop())
	mux := chi.NewRouter()
	mux.Post("/roles", h.CreateRole)
	mux.Post("/roles/{id}", h.UpdateRole)
	mux.Post("/users/{id}/roles/{roleId}", h.GrantRole)
	mux.Delete("/users/{id}/roles/{roleId}", h.RevokeRole)
	create := `{"key":"reader","name":"Reader","permissions":["reports.read"]}`
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, accessRequest("POST", "/roles", create))
	if w.Code != 201 || svc.create.Actor != testActor || len(svc.create.Permissions) != 1 {
		t.Fatal("create lost authenticated principal or role", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, accessRequest("POST", "/roles/"+string(testRole), `{"key":"reader","name":"Reader","expectedVersion":7}`))
	if w.Code != 200 || svc.update.Actor != testActor || svc.update.RoleID != testRole || svc.update.ExpectedVersion != 7 {
		t.Fatal("update lost expected version or path", w.Code)
	}
	for _, method := range []string{"POST", "DELETE"} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, accessRequest(method, "/users/33333333-3333-4333-8333-333333333333/roles/"+string(testRole), `{"expectedRoleVersion":4,"expectedAccessVersion":9}`))
		if w.Code != 200 || svc.assignment.Actor != testActor || svc.assignment.UserID != "33333333-3333-4333-8333-333333333333" || svc.assignment.RoleID != testRole || svc.assignment.ExpectedAccessVersion != 9 || svc.assignment.ExpectedRoleVersion != 4 || svc.assignment.Grant != (method == "POST") {
			t.Fatal("assignment lost target, action, versions or authority", w.Code, svc.assignment)
		}
	}
	before := svc.calls
	for _, body := range []string{`{"actor":{}}`, `{"system":true}`, `{"key":"reader","tokenHash":"spoof"}`, create + create} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, accessRequest("POST", "/roles", body))
		if w.Code != 400 || svc.calls != before {
			t.Fatal("invalid JSON or authority fields reached service", body, w.Code)
		}
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/roles", strings.NewReader(create)))
	if w.Code != 401 || svc.calls != before {
		t.Fatal("missing authentication reached service")
	}
}

func TestRolePaginationAndJSON(t *testing.T) {
	svc := &captureService{}
	h := New(svc, zap.NewNop())
	for _, query := range []string{"?limit=x", "?limit=1&limit=2", "?unknown=1", "?after=%ZZ"} {
		before := svc.calls
		w := httptest.NewRecorder()
		h.ListRoles(w, accessRequest("GET", "/roles"+query, ""))
		if w.Code != 400 || svc.calls != before {
			t.Fatal("ambiguous query reached service", query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ListRoles(w, accessRequest("GET", "/roles?limit=1&after=before", ""))
	var page RolePageResponse
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.NextAfter != "reader" || svc.after != "before" || svc.limit != 1 {
		t.Fatal("keyset contract", w.Body.String(), err)
	}
	encoded, err := json.Marshal(accessResponse(domain.UserAccess{Version: 1}))
	if err != nil || string(encoded) != `{"accessVersion":1,"roleIds":[],"permissions":[]}` {
		t.Fatal("empty permissions must be arrays", string(encoded), err)
	}
}

func TestAccessErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrInvalidRole, 400, "invalid_role"},
		{domain.ErrInvalidPermission, 400, "invalid_permission"},
		{domain.ErrForbidden, 403, "forbidden"},
		{domain.ErrFreshAuthRequired, 403, "fresh_auth_required"},
		{domain.ErrRoleNotFound, 404, "role_not_found"},
		{domain.ErrConflict, 409, "access_conflict"},
		{domain.ErrTargetUnavailable, 409, "target_unavailable"},
		{errors.New("password=do-not-log"), 503, "temporarily_unavailable"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			h := New(&captureService{err: tc.err}, zap.New(core))
			w := httptest.NewRecorder()
			h.CreateRole(w, accessRequest("POST", "/roles", `{}`))
			if w.Code != tc.status || !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) || strings.Contains(w.Body.String(), "do-not-log") {
				t.Fatal("public error mapping", w.Code, w.Body.String())
			}
			for _, entry := range logs.All() {
				if strings.Contains(entry.Message, "do-not-log") || strings.Contains(strings.TrimSpace(logFields(entry.ContextMap())), "do-not-log") {
					t.Fatal("dependency details leaked to logs")
				}
			}
		})
	}
}

func logFields(fields map[string]any) string {
	encoded, _ := json.Marshal(fields)
	return string(encoded)
}
