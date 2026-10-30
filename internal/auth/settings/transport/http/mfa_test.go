package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type mfaSettingsStub struct {
	input          service.MFAUpdateInput
	reads, updates int
	err            error
}

func (s *mfaSettingsStub) Read(context.Context, accessservice.Principal) (domain.MFASnapshot, error) {
	s.reads++
	return domain.MFASnapshot{Version: 3, Policy: domain.MFAPolicy{Mode: domain.MFAOptional}}, s.err
}

func (s *mfaSettingsStub) Update(_ context.Context, input service.MFAUpdateInput) (domain.MFASnapshot, error) {
	s.updates++
	s.input = input
	return domain.MFASnapshot{Version: 4, Policy: input.Policy}, s.err
}

func TestMFASettingsHTTP(t *testing.T) {
	s := &mfaSettingsStub{}
	h := NewMFA(s, zap.NewNop())
	auth := sessionhttp.Auth{UserID: "f9000000-0000-4000-8000-000000000001", TokenHash: strings.Repeat("a", 64)}
	call := func(method, body string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/admin/auth/settings/mfa", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if authenticated {
			r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), auth))
		}
		w := httptest.NewRecorder()
		if method == "GET" {
			h.Read(w, r)
		} else {
			h.Update(w, r)
		}
		return w
	}
	require.Equal(t, 401, call("GET", "", false).Code)
	require.Zero(t, s.reads)
	read := call("GET", "", true)
	require.Equal(t, 200, read.Code)
	require.Contains(t, read.Body.String(), `"mode":"optional"`)
	for _, body := range []string{`{}`, `{"policy":null}`, `{"policy":{"mode":"optional"},"ready":true}`, `{"policy":{"mode":"optional"},"actor":"forged"}`} {
		require.Equal(t, 400, call("POST", body, true).Code)
	}
	require.Zero(t, s.updates)
	w := call("POST", `{"expectedVersion":3,"policy":{"mode":"required"}}`, true)
	require.Equal(t, 200, w.Code)
	require.Equal(t, auth.UserID, s.input.Actor.UserID)
	require.Equal(t, auth.TokenHash, s.input.Actor.TokenHash)
	require.Equal(t, int64(3), s.input.ExpectedVersion)
	require.Equal(t, domain.MFARequired, s.input.Policy.Mode)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Empty(t, w.Header().Values("Set-Cookie"))
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrInvalidMFAPolicy, 400, "invalid_mfa_policy"},
		{domain.ErrPolicyConflict, 409, "mfa_policy_conflict"},
		{domain.ErrMethodNotReady, 409, "mfa_not_ready"},
	} {
		s.err = tc.err
		w = call(http.MethodPost, `{"expectedVersion":3,"policy":{"mode":"required"}}`, true)
		require.Equal(t, tc.status, w.Code)
		require.Contains(t, w.Body.String(), tc.code)
	}
}
