package http

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestProjectStateHTTP(t *testing.T) {
	svc := &catalogServiceStub{}
	h := New(svc, zap.NewNop())
	router := chi.NewRouter()
	router.Post("/projects/{id}/suspend", h.Suspend)
	router.Post("/projects/{id}/resume", h.Resume)
	router.Post("/projects/{id}/retry", h.Retry)
	const id = "1c82c477-3a57-4823-8c49-a476550d8a21"
	const operation = "22222222-2222-4222-8222-222222222222"
	const body = `{"operationId":"` + operation + `","expectedVersion":1,"expectedGeneration":1,"reason":"incident-123"}`
	auth := sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	request := func(path, input string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/projects/"+id+"/"+path, strings.NewReader(input))
		r.Header.Set("Content-Type", "application/json")
		if authenticated {
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), auth))
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("mutation refreshed cookie or became cacheable")
		}
		return w
	}
	for path, action := range map[string]domain.Action{"suspend": domain.Suspend, "resume": domain.Resume, "retry": domain.RetryPreparation} {
		w := request(path, body, true)
		if w.Code != 200 || svc.action != action || svc.actor.UserID != auth.UserID || svc.actor.TokenHash != auth.TokenHash ||
			svc.change.ProjectID != id || svc.change.OperationID != operation || svc.change.ExpectedVersion != 1 || svc.change.ExpectedGeneration != 1 || svc.change.Reason != "incident-123" {
			t.Fatal("untrusted state command mapping", path, w.Code)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil || len(fields) != 6 {
			t.Fatal("unexpected receipt DTO", err)
		}
	}
	before := svc.calls
	if w := request("suspend", body, false); w.Code != 401 || svc.calls != before {
		t.Fatal("anonymous mutation reached service")
	}
	for _, input := range []string{"", "{} {}", `{"actorId":"forged"}`, `{"expectedVersion":"1"}`} {
		if w := request("suspend", input, true); w.Code != 400 || svc.calls != before {
			t.Fatal("invalid body reached service", w.Code)
		}
	}
	if w := request("suspend?actor=forged", body, true); w.Code != 400 || svc.calls != before {
		t.Fatal("unexpected query reached service", w.Code)
	}
	for _, failure := range []struct {
		err    error
		status int
		code   string
	}{
		{operatordomain.ErrForbidden, 403, "forbidden"},
		{operatordomain.ErrFreshAuthRequired, 428, "fresh_auth_required"},
		{domain.ErrConflict, 409, "project_conflict"},
		{domain.ErrInvalidTransition, 409, "invalid_transition"},
		{domain.ErrNotFound, 404, "project_not_found"},
		{domain.ErrUnavailable, 503, "temporarily_unavailable"},
	} {
		svc.err = failure.err
		w := request("suspend", body, true)
		if w.Code != failure.status || !strings.Contains(w.Body.String(), failure.code) {
			t.Fatal("incorrect mutation error", w.Code, w.Body.String())
		}
	}
}
