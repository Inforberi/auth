package http_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	directoryhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type userServiceStub struct {
	target domain.DirectoryTarget
	actor  operatordomain.Principal
	input  accountservice.UserListInput
	id     accountdomain.UserID
	err    error
	calls  int
}

func (s *userServiceStub) ListProjectUsers(_ context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, input accountservice.UserListInput) (accountservice.UserPage, error) {
	s.calls++
	s.actor, s.target, s.input = actor, target, input
	return accountservice.UserPage{}, s.err
}

func (s *userServiceStub) ReadProjectUser(_ context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, id accountdomain.UserID) (accountservice.UserDetail, error) {
	s.calls++
	s.actor, s.target, s.id = actor, target, id
	return accountservice.UserDetail{}, s.err
}

func TestPlatformUsersHTTPShapeAndScope(t *testing.T) {
	const query = "?expectedVersion=3&expectedGeneration=4"
	for _, tc := range []struct {
		path, body string
		auth       bool
		err        error
		status     int
		calls      int
	}{
		{"/users" + query + "&email=person%40example.test&status=active&limit=2", "", true, nil, 200, 1},
		{"/users/user" + query, "", true, nil, 200, 1},
		{"/users/user" + query, "", true, accountdomain.ErrAccountNotFound, 404, 1},
		{"/users" + query, "", true, operatordomain.ErrForbidden, 403, 1},
		{"/users" + query, "", false, nil, 401, 0},
		{"/users" + query, "{}", true, nil, 400, 0},
		{"/users", "", true, nil, 400, 0},
		{"/users" + query + "&limit=1&limit=2", "", true, nil, 400, 0},
		{"/users" + query + "&limit=invalid", "", true, nil, 400, 0},
		{"/users" + query + "&actor=forged", "", true, nil, 400, 0},
		{"/users/user" + query + "&email=ignored", "", true, nil, 400, 0},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			s := &userServiceStub{err: tc.err}
			h := directoryhttp.NewUsers(s, nil)
			router := chi.NewRouter()
			router.Get("/projects/{id}/users", h.List)
			router.Get("/projects/{id}/users/{userId}", h.Read)
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
				require.EqualValues(t, "project", s.target.ProjectID)
				require.EqualValues(t, 3, s.target.ExpectedVersion)
				require.EqualValues(t, 4, s.target.ExpectedGeneration)
				require.Equal(t, "proof", s.actor.TokenHash)
			}
			if tc.status == 200 {
				require.NotContains(t, w.Body.String(), "tokenHash")
				require.NotContains(t, w.Body.String(), "secret")
			}
		})
	}
}
