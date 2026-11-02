package http

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestCreateProjectHTTP(t *testing.T) {
	svc := &catalogServiceStub{}
	h := New(svc, nil)
	const body = `{"operationId":"22222222-2222-4222-8222-222222222222","slug":"shop","name":"Shop","reason":"incident"}`
	actor := sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	call := func(path, input string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(input))
		r.Header.Set("Content-Type", "application/json")
		if authenticated {
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), actor))
		}
		w := httptest.NewRecorder()
		h.Create(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
			t.Fatal("creation cached or changed cookies")
		}
		return w
	}
	w := call("/projects", body, true)
	if w.Code != 201 || w.Header().Get("Location") != "/api/v1/platform/projects/1c82c477-3a57-4823-8c49-a476550d8a21" || svc.actor.UserID != actor.UserID || svc.actor.TokenHash != actor.TokenHash || svc.creation.Slug != "shop" || svc.creation.Name != "Shop" || svc.creation.Reason != "incident" {
		t.Fatal("incorrect creation request/result", w.Code)
	}
	var result struct {
		Project  map[string]json.RawMessage `json:"project"`
		Replayed bool                       `json:"replayed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Project) != 10 || result.Replayed {
		t.Fatal("unsafe creation DTO", err)
	}
	svc.replayed = true
	if w := call("/projects", body, true); w.Code != 200 || !strings.Contains(w.Body.String(), `"replayed":true`) {
		t.Fatal("incorrect replay response")
	}
	before := svc.calls
	if w := call("/projects", body, false); w.Code != 401 || svc.calls != before {
		t.Fatal("anonymous creation")
	}
	for _, bad := range []string{`{"origin":"https://evil.example"}`, `{"storageTarget":"elsewhere"}`, `{"actorId":"forged"}`, `{"databaseName":"db"}`, body + ` {}`} {
		if w := call("/projects", bad, true); w.Code != 400 || svc.calls != before {
			t.Fatal("untrusted field reached service")
		}
	}
	if w := call("/projects?actor=forged", body, true); w.Code != 400 || svc.calls != before {
		t.Fatal("query actor accepted")
	}
}
