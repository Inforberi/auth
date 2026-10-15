package router

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

type contractActivation struct {
	calls int
	err   error
}

func (s *contractActivation) Activate(context.Context, string, string, string, string) error {
	s.calls++
	return s.err
}

func TestInvitationHTTPContract(t *testing.T) {
	const path = "/api/v1/auth/invitations/activate"
	for _, tc := range []struct {
		name, method, origin, body string
		status, calls              int
		err                        error
		code                       string
	}{
		{"success", "POST", "https://localhost:8443", `{"token":"token","password":"ExamplePass2","confirmPassword":"ExamplePass2"}`, 200, 1, nil, ""},
		{"GET", "GET", "https://localhost:8443", "", 405, 0, nil, ""},
		{"origin", "POST", "https://evil.example.com", `{}`, 403, 0, nil, "invalid_origin"},
		{"missing origin", "POST", "", `{}`, 403, 0, nil, "invalid_origin"},
		{"JSON", "POST", "https://localhost:8443", `{`, 400, 0, nil, "invalid_json"},
		{"unknown field", "POST", "https://localhost:8443", `{"role":"admin"}`, 400, 0, nil, "invalid_json"},
		{"token", "POST", "https://localhost:8443", `{}`, 400, 1, accountdomain.ErrInvalidInvitation, "invalid_invitation"},
		{"limit", "POST", "https://localhost:8443", `{}`, 429, 1, passworddomain.ErrRecoveryLimited, "rate_limited"},
		{"hash budget", "POST", "https://localhost:8443", `{}`, 503, 1, passworddomain.ErrHashBusy, "temporarily_unavailable"},
		{"SQL failure", "POST", "https://localhost:8443", `{}`, 503, 1, errors.New("SQL secret payload"), "temporarily_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &contractActivation{err: tc.err}
			h := contractHandlers("test")
			h.Activation = passwordhttp.NewActivation(s, zap.NewNop())
			r := httptest.NewRequest(tc.method, path, strings.NewReader(tc.body))
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != tc.status || s.calls != tc.calls {
				t.Fatal(w.Code, s.calls, w.Body.String())
			}
			if len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "secret") {
				t.Fatal("cookie or secret leaked")
			}
			if tc.code != "" && !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatal(w.Body.String())
			}
			if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if tc.status == 429 && w.Header().Get("Retry-After") != "60" {
				t.Fatal("missing retry bound")
			}
		})
	}
	h := contractHandlers("test")
	h.Activation = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://localhost:8443")
	New(h).ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("disabled invitation published", w.Code)
	}
	doc := readAPI(t)
	if len(doc.Paths[path]["post"].Responses) == 0 {
		t.Fatal("missing activation API contract")
	}
}
