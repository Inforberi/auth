package http_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
	roleshttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestPlatformRoleDirectoryHTTP(t *testing.T) {
	const query = "?expectedVersion=3&expectedGeneration=4"
	for _, tc := range []struct {
		path, body string
		auth       bool
		err        error
		status     int
		calls      int
	}{
		{"/roles" + query, "", true, nil, 200, 1},
		{"/roles/role" + query, "", true, nil, 200, 1},
		{"/roles" + query + "&limit=2&afterKey=editor", "", true, nil, 200, 1},
		{"/roles" + query, "", true, operatordomain.ErrForbidden, 403, 1},
		{"/roles/role" + query, "", true, accessdomain.ErrRoleNotFound, 404, 1},
		{"/roles" + query, "", false, nil, 401, 0},
		{"/roles" + query, "{}", true, nil, 400, 0},
		{"/roles", "", true, nil, 400, 0},
		{"/roles" + query + "&limit=oops", "", true, nil, 400, 0},
		{"/roles" + query + "&limit=2&limit=3", "", true, nil, 400, 0},
		{"/roles/role" + query + "&afterKey=editor", "", true, nil, 400, 0},
		{"/roles" + query + "&actor=forged", "", true, nil, 400, 0},
		{"/roles" + query + "&afterKey=" + strings.Repeat("a", 1024), "", true, nil, 400, 0},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			s := &roleServiceStub{err: tc.err, page: roleservice.ProjectRolePage{Roles: []accessdomain.Role{{Key: "editor", Version: 2}}, NextAfterKey: "editor"}}
			h := roleshttp.NewRoles(s, nil)
			router := chi.NewRouter()
			router.Get("/projects/{id}/roles", h.ListRoles)
			router.Get("/projects/{id}/roles/{roleId}", h.ReadRole)
			r := httptest.NewRequest("GET", "/projects/project"+tc.path, strings.NewReader(tc.body))
			if tc.auth {
				r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "operator", TokenHash: "proof"}))
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.calls, s.calls)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			if tc.calls > 0 {
				require.EqualValues(t, "project", s.query.Target.ProjectID)
				require.EqualValues(t, 3, s.query.Target.ExpectedVersion)
				require.EqualValues(t, 4, s.query.Target.ExpectedGeneration)
				require.Equal(t, "proof", s.actor.TokenHash)
			}
			if tc.status == 200 && !strings.HasPrefix(tc.path, "/roles/role") {
				var response roleshttp.PlatformRolePageResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				require.Equal(t, "editor", response.NextAfterKey)
				require.Len(t, response.Roles, 1)
				require.NotContains(t, w.Body.String(), "permissions")
			}
		})
	}
}
