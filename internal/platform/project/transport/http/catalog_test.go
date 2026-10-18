package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
)

type catalogServiceStub struct {
	calls int
	actor operatordomain.Principal
	input service.ListInput
	id    domain.ID
	err   error
}

func (s *catalogServiceStub) List(_ context.Context, actor operatordomain.Principal, input service.ListInput) (service.ListResult, error) {
	s.calls++
	s.actor, s.input = actor, input
	return service.ListResult{}, s.err
}

func (s *catalogServiceStub) Read(_ context.Context, actor operatordomain.Principal, id domain.ID) (domain.Project, error) {
	s.calls++
	s.actor, s.id = actor, id
	return domain.Project{ID: id, Slug: "shop", Name: "Shop", Origin: "https://shop.example", DesiredState: domain.Enabled, Phase: domain.Ready, Version: 3, Generation: 2}, s.err
}

func TestProjectReadHTTP(t *testing.T) {
	svc := &catalogServiceStub{}
	h := New(svc, zap.NewNop())
	router := chi.NewRouter()
	router.Get("/projects", h.List)
	router.Get("/projects/{id}", h.Read)
	const id = "1c82c477-3a57-4823-8c49-a476550d8a21"
	actor := sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	request := func(path string, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if authenticated {
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), actor))
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("read cached or changed cookies")
		}
		return w
	}
	if w := request("/projects", false); w.Code != 401 || svc.calls != 0 {
		t.Fatal("anonymous access", w.Code)
	}
	if w := request("/projects", true); w.Code != 200 || svc.input.Limit != 50 || !strings.Contains(w.Body.String(), `"projects":[]`) {
		t.Fatal("default/empty page", w.Code, w.Body.String())
	}
	if svc.actor.UserID != actor.UserID || svc.actor.TokenHash != actor.TokenHash {
		t.Fatal("untrusted actor")
	}
	if w := request("/projects?limit=2&phase=ready&before=cursor", true); w.Code != 200 || svc.input.Limit != 2 || svc.input.Phase != domain.Ready || svc.input.Before != "cursor" {
		t.Fatal("query mapping", w.Code)
	}
	for _, query := range []string{"limit=2&limit=3", "phase=ready&phase=failed", "before=a&before=b", "offset=100", "actor=forged", "limit=wrong", "limit=", "before=%zz"} {
		before := svc.calls
		if w := request("/projects?"+query, true); w.Code != 400 || before != svc.calls {
			t.Fatal("invalid query reached service", query, w.Code)
		}
	}
	w := request("/projects/"+id, true)
	if w.Code != 200 || svc.id != id {
		t.Fatal("path id mapping", w.Code)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil || len(fields) != 10 {
		t.Fatal("unexpected project DTO", err)
	}
	for _, name := range []string{"storageTarget", "databaseName", "credentialRef", "schemaVersion", "password", "secret"} {
		if _, exposed := fields[name]; exposed {
			t.Fatal("private binding field exposed", name)
		}
	}
	before := svc.calls
	if w := request("/projects/"+id+"?actor=forged", true); w.Code != 400 || before != svc.calls {
		t.Fatal("card accepted query actor", w.Code)
	}
	for _, failure := range []struct {
		err    error
		status int
		code   string
	}{
		{operatordomain.ErrForbidden, 403, "forbidden"},
		{domain.ErrInvalidPage, 400, "invalid_query"},
		{domain.ErrInvalidProject, 400, "invalid_project"},
		{domain.ErrNotFound, 404, "project_not_found"},
		{operatordomain.ErrUnavailable, 503, "temporarily_unavailable"},
		{domain.ErrUnavailable, 503, "temporarily_unavailable"},
		{errors.New("postgres://secret:password@private-host"), 503, "temporarily_unavailable"},
	} {
		svc.err = failure.err
		w := request("/projects/"+id, true)
		if w.Code != failure.status || !strings.Contains(w.Body.String(), failure.code) || strings.Contains(w.Body.String(), "private-host") || strings.Contains(w.Body.String(), "password@") {
			t.Fatal("unsafe error mapping", w.Code, w.Body.String())
		}
	}
}
