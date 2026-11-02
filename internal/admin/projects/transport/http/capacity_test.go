package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/admission"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type capacityStub struct {
	actor, project  domain.ID
	calls, releases int
	err             error
}

func (s *capacityStub) Acquire(_ context.Context, actor, project domain.ID) (func(), error) {
	s.calls++
	s.actor, s.project = actor, project
	return func() { s.releases++ }, s.err
}

func TestCapacityHTTP(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		retry  string
	}{
		{"ok", nil, 204, ""},
		{"rate", admission.ErrRateLimited, 429, "60"},
		{"busy", admission.ErrBusy, 503, "1"},
		{"unavailable", errors.New("private backend detail"), 503, "1"},
		{"invalid project", domain.ErrInvalidProject, 400, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := &capacityStub{err: test.err}
			called := false
			router := chi.NewRouter()
			router.With(Capacity(gate)).Get("/projects/{id}", func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) })
			r := httptest.NewRequest("GET", "/projects/33333333-3333-4333-8333-333333333333", nil)
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111"}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
			require.Equal(t, test.retry, w.Header().Get("Retry-After"))
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, domain.ID("33333333-3333-4333-8333-333333333333"), gate.project)
			require.Equal(t, domain.ID("11111111-1111-4111-8111-111111111111"), gate.actor)
			require.Equal(t, test.err == nil, called)
			require.NotContains(t, w.Body.String(), "private backend detail")
			if called {
				require.Equal(t, 1, gate.releases)
			} else {
				require.Zero(t, gate.releases)
			}
		})
	}
	gate := &capacityStub{}
	w := httptest.NewRecorder()
	Capacity(gate)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated request reached handler") })).ServeHTTP(w, httptest.NewRequest("GET", "/projects", nil))
	require.Equal(t, 401, w.Code)
	require.Zero(t, gate.calls)
}
