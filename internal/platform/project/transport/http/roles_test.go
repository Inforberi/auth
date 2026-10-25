package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
)

type roleServiceStub struct {
	assignment         domain.RoleAssignment
	assigned           domain.RoleAssignmentResult
	command            domain.RoleCreation
	project, operation domain.ID
	actor              operatordomain.Principal
	create             domain.RoleCreationResult
	outcome            domain.RoleOutcome
	err                error
	calls              int
	query              service.ProjectRoleQuery
	page               service.ProjectRolePage
	role               accessdomain.Role
}

func (s *roleServiceStub) ListProjectRoles(_ context.Context, actor operatordomain.Principal, query service.ProjectRoleQuery) (service.ProjectRolePage, error) {
	s.calls++
	s.actor, s.query = actor, query
	return s.page, s.err
}

func (s *roleServiceStub) ReadProjectRole(_ context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accessdomain.RoleID) (accessdomain.Role, error) {
	s.calls++
	s.actor, s.query.Target, s.role.ID = actor, target, id
	return s.role, s.err
}

func (s *roleServiceStub) ChangeRoleAssignment(_ context.Context, actor operatordomain.Principal, command domain.RoleAssignment) (domain.RoleAssignmentResult, error) {
	s.calls++
	s.actor, s.assignment = actor, command
	return s.assigned, s.err
}

func (s *roleServiceStub) CreateRole(_ context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationResult, error) {
	s.calls++
	s.actor, s.command = actor, command
	return s.create, s.err
}

func (s *roleServiceStub) ReadRoleOutcome(_ context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleOutcome, error) {
	s.calls++
	s.actor, s.project, s.operation = actor, project, operation
	return s.outcome, s.err
}

func (s *roleServiceStub) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleOutcome, error) {
	return s.ReadRoleOutcome(ctx, actor, project, operation)
}

func TestCreatePlatformRoleHTTP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result domain.RoleCreationResult
		err    error
		status int
	}{
		{"create", domain.RoleCreationResult{Role: accessdomain.Role{Key: "editor"}, CatalogRecorded: true}, nil, 201},
		{"replay", domain.RoleCreationResult{Replayed: true, CatalogRecorded: true}, nil, 200},
		{"missing catalog evidence", domain.RoleCreationResult{}, nil, 201},
		{"unknown", domain.RoleCreationResult{}, domain.ErrOperationOutcomeUnknown, 202},
		{"role conflict", domain.RoleCreationResult{}, accessdomain.ErrConflict, 409},
		{"MFA unavailable", domain.RoleCreationResult{}, accessdomain.ErrMFANotReady, 409},
		{"revoked", domain.RoleCreationResult{}, operatordomain.ErrForbidden, 403},
		{"fresh proof", domain.RoleCreationResult{}, operatordomain.ErrFreshAuthRequired, 428},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &roleServiceStub{create: tc.result, err: tc.err}
			h := NewRoles(s, nil)
			router := chi.NewRouter()
			router.Post("/projects/{id}/roles", h.Create)
			r := httptest.NewRequest("POST", "/projects/11111111-1111-4111-8111-111111111111/roles", strings.NewReader(`{"operationId":"22222222-2222-4222-8222-222222222222","expectedVersion":3,"expectedGeneration":4,"key":"editor","name":"Editor","permissions":[],"reason":"test"}`))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "33333333-3333-4333-8333-333333333333", TokenHash: "proof"}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, domain.ID("11111111-1111-4111-8111-111111111111"), s.command.ProjectID)
			require.Equal(t, "proof", s.actor.TokenHash)
			if tc.status < 300 {
				require.Equal(t, "/api/v1/platform/projects/11111111-1111-4111-8111-111111111111/role-operations/22222222-2222-4222-8222-222222222222", w.Header().Get("Location"))
				var result CreatePlatformRoleResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
				if tc.status == 202 {
					require.Equal(t, "unknown", result.Status)
					require.Nil(t, result.Role)
				} else {
					require.Equal(t, "committed", result.Status)
				}
			}
		})
	}
}

func TestPlatformRoleHTTPShapeAndScope(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		auth               bool
		status, calls      int
	}{
		{"POST", "/projects/p/roles", `{}`, false, 401, 0},
		{"POST", "/projects/p/roles?unexpected=1", `{}`, true, 400, 0},
		{"POST", "/projects/p/roles", `{"actor":"forged"}`, true, 400, 0},
		{"POST", "/projects/p/roles", strings.Repeat(" ", 33<<10) + `{}`, true, 400, 0},
		{"GET", "/projects/p/role-operations/o", ``, true, 200, 1},
		{"POST", "/projects/p/role-operations/o/reconcile", ``, true, 200, 1},
		{"POST", "/projects/p/role-operations/o/reconcile", `{}`, true, 400, 0},
		{"GET", "/projects/p/role-operations/o", `{}`, true, 400, 0},
	} {
		t.Run(tc.method+tc.path+tc.body[:min(len(tc.body), 10)], func(t *testing.T) {
			s := &roleServiceStub{}
			h := NewRoles(s, nil)
			router := chi.NewRouter()
			router.Post("/projects/{id}/roles", h.Create)
			router.Get("/projects/{id}/role-operations/{operationId}", h.Read)
			router.Post("/projects/{id}/role-operations/{operationId}/reconcile", h.Reconcile)
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.auth {
				r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "actor"}))
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.calls, s.calls)
			if s.calls > 0 {
				require.Equal(t, domain.ID("p"), s.project)
				require.Equal(t, domain.ID("o"), s.operation)
				require.NotContains(t, w.Body.String(), `"role"`)
			}
		})
	}
}
