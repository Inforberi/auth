package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type policyServiceStub struct {
	calls   int
	actor   operatordomain.Principal
	command domain.AuthPolicyUpdate
	target  domain.DirectoryTarget
	result  domain.AuthPolicyResult
	outcome domain.AuthPolicyOutcome
	err     error
}

func (s *policyServiceStub) ReadAuthPolicy(_ context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (settingsdomain.Snapshot, error) {
	s.calls++
	s.actor, s.target = actor, target
	return s.result.Snapshot, s.err
}

func (s *policyServiceStub) UpdateAuthPolicy(_ context.Context, actor operatordomain.Principal, command domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error) {
	s.calls++
	s.actor, s.command = actor, command
	return s.result, s.err
}

func (s *policyServiceStub) ReadAuthPolicyOutcome(_ context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.AuthPolicyOutcome, error) {
	s.calls++
	s.actor = actor
	s.command.ProjectID, s.command.OperationID = project, operation
	return s.outcome, s.err
}

const completePolicyBody = `{"operationId":"22222222-2222-4222-8222-222222222222","expectedVersion":3,"expectedGeneration":4,"expectedPolicyVersion":1,"reason":"maintenance","policy":{"methods":{"password":false,"emailOtp":false,"google":false,"telegram":false},"registration":{"enabled":false,"google":false,"telegram":false},"passwordEmailVerification":"disabled","tokenIssuance":{"sessionExchange":false,"native":false}}}`

func policyHTTP(t *testing.T, s *policyServiceStub, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAuthPolicy(s, settingsdomain.PublicMethods{}, nil)
	router := chi.NewRouter()
	router.Get("/projects/{id}/auth/settings", h.Read)
	router.Post("/projects/{id}/auth/settings", h.Update)
	router.Get("/projects/{id}/auth/settings/operations/{operationId}", h.ReadOutcome)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if auth {
		r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "actor", TokenHash: "proof"}))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestPlatformAuthPolicyHTTP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"committed", nil, 200},
		{"unknown", domain.ErrOperationOutcomeUnknown, 202},
		{"unready", settingsdomain.ErrMethodNotReady, 409},
		{"version", settingsdomain.ErrPolicyConflict, 409},
		{"missing settings", settingsdomain.ErrNotInitialized, 409},
		{"forbidden", operatordomain.ErrForbidden, 403},
		{"fresh proof", operatordomain.ErrFreshAuthRequired, 428},
		{"expired", domain.ErrAdmissionExpired, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &policyServiceStub{result: domain.AuthPolicyResult{Snapshot: settingsdomain.Snapshot{Version: 2}, Changed: true}, err: tc.err}
			w := policyHTTP(t, s, "POST", "/projects/project/auth/settings", completePolicyBody, true)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Equal(t, 1, s.calls)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, "proof", s.actor.TokenHash)
			require.Equal(t, domain.ID("project"), s.command.ProjectID)
			require.EqualValues(t, 1, s.command.ExpectedPolicyVersion)
			require.NotContains(t, w.Body.String(), "ReceiptAdmissionID")
			if tc.status < 300 {
				require.Equal(t, "/api/v1/platform/projects/project/auth/settings/operations/22222222-2222-4222-8222-222222222222", w.Header().Get("Location"))
				var response ProjectAuthPolicyResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				if tc.status == 202 {
					require.Equal(t, "unknown", response.Status)
					require.Nil(t, response.Settings)
					require.Nil(t, response.Changed)
				} else {
					require.EqualValues(t, 2, response.Settings.Version)
					require.True(t, *response.Changed)
				}
			}
		})
	}
}

func TestPlatformAuthPolicyShapeAndScope(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		auth                     bool
		status, calls            int
	}{
		{"unauthenticated", "POST", "/projects/p/auth/settings", completePolicyBody, false, 401, 0},
		{"query", "POST", "/projects/p/auth/settings?actor=x", completePolicyBody, true, 400, 0},
		{"actor injection", "POST", "/projects/p/auth/settings", `{"actor":"forged"}`, true, 400, 0},
		{"absent policy", "POST", "/projects/p/auth/settings", `{}`, true, 400, 0},
		{"missing boolean", "POST", "/projects/p/auth/settings", strings.Replace(completePolicyBody, `"password":false,`, "", 1), true, 400, 0},
		{"unknown nested field", "POST", "/projects/p/auth/settings", strings.Replace(completePolicyBody, `"native":false`, `"native":false,"deployment":"on"`, 1), true, 400, 0},
		{"bounded body", "POST", "/projects/p/auth/settings", strings.Repeat(" ", 8<<10) + completePolicyBody, true, 400, 0},
		{"read", "GET", "/projects/p/auth/settings?expectedVersion=3&expectedGeneration=4", "", true, 200, 1},
		{"missing versions", "GET", "/projects/p/auth/settings", "", true, 400, 0},
		{"read body", "GET", "/projects/p/auth/settings?expectedVersion=3&expectedGeneration=4", "{}", true, 400, 0},
		{"outcome", "GET", "/projects/p/auth/settings/operations/o", "", true, 200, 1},
		{"outcome body", "GET", "/projects/p/auth/settings/operations/o", "{}", true, 400, 0},
		{"outcome query", "GET", "/projects/p/auth/settings/operations/o?actor=x", "", true, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &policyServiceStub{}
			w := policyHTTP(t, s, tc.method, tc.path, tc.body, tc.auth)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Equal(t, tc.calls, s.calls)
			if tc.calls > 0 {
				require.Equal(t, "proof", s.actor.TokenHash)
			}
		})
	}
}
