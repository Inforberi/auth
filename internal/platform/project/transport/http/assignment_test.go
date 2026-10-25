package http

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestPlatformAssignmentHTTP(t *testing.T) {
	for _, action := range []domain.RoleAction{domain.RoleGrant, domain.RoleRevoke} {
		for _, unknown := range []bool{false, true} {
			s := &roleServiceStub{assigned: domain.RoleAssignmentResult{RoleAssignmentSnapshot: domain.RoleAssignmentSnapshot{AccessVersion: 2, Changed: true}}}
			if unknown {
				s.err = domain.ErrOperationOutcomeUnknown
			}
			h := NewRoles(s, nil)
			router := chi.NewRouter()
			router.Post("/projects/{id}/users/{userId}/roles/{roleId}/grant", h.Grant)
			router.Post("/projects/{id}/users/{userId}/roles/{roleId}/revoke", h.Revoke)
			r := httptest.NewRequest("POST", "/projects/project/users/user/roles/role/"+string(action), strings.NewReader(`{"operationId":"op","expectedVersion":3,"expectedGeneration":4,"expectedRoleVersion":5,"expectedAccessVersion":6,"reason":"test"}`))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "operator", TokenHash: "proof"}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			status := 200
			if unknown {
				status = 202
			}
			require.Equal(t, status, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Contains(t, w.Header().Get("Location"), "/projects/project/role-operations/op")
			require.Equal(t, action, s.assignment.Action)
			require.Equal(t, domain.ID("project"), s.assignment.ProjectID)
			require.Equal(t, "user", string(s.assignment.UserID))
			require.Equal(t, "role", string(s.assignment.RoleID))
			require.Equal(t, "operator", string(s.actor.UserID))
			require.EqualValues(t, 5, s.assignment.ExpectedRoleVersion)
			require.EqualValues(t, 6, s.assignment.ExpectedAccessVersion)
			var response PlatformAssignmentResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			if unknown {
				require.Nil(t, response.Changed)
				require.Nil(t, response.Role)
				require.Equal(t, "unknown", response.Status)
			} else {
				require.NotNil(t, response.Changed)
				require.True(t, *response.Changed)
			}
		}
	}
	for _, body := range []string{`{"action":"grant"}`, `{"userId":"foreign"}`, `{"actor":"forged"}`, strings.Repeat(" ", 9<<10) + `{}`} {
		s := &roleServiceStub{}
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "operator"}))
		w := httptest.NewRecorder()
		NewRoles(s, nil).Grant(w, r)
		require.Equal(t, 400, w.Code)
		require.Zero(t, s.calls)
	}
}
