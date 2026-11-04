package settingshttp_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

type emailMFASettingsStub struct {
	calls int
	input service.EmailMFAUpdate
	err   error
}

func (s *emailMFASettingsStub) Read(context.Context, accessservice.Principal) (domain.EmailMFASnapshot, error) {
	s.calls++
	return domain.EmailMFASnapshot{Version: 3, Allowed: false}, s.err
}

func (s *emailMFASettingsStub) Update(_ context.Context, input service.EmailMFAUpdate) (domain.EmailMFASnapshot, error) {
	s.calls++
	s.input = input
	return domain.EmailMFASnapshot{Version: 4, Allowed: input.Allowed}, s.err
}

func TestEmailMFASettingsHTTP(t *testing.T) {
	svc := &emailMFASettingsStub{}
	h := settingshttp.NewEmailMFA(svc, zap.NewNop())
	auth := sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 2}
	for _, body := range []string{`{"expectedVersion":3}`, `{"expectedVersion":3,"allowed":null}`, `{"expectedVersion":3,"allowed":true,"ready":true}`} {
		r := httptest.NewRequest("POST", "https://auth.example/settings", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), auth))
		w := httptest.NewRecorder()
		h.Update(w, r)
		require.Equal(t, 400, w.Code)
	}
	require.Zero(t, svc.calls)
	r := httptest.NewRequest("POST", "https://auth.example/settings", strings.NewReader(`{"expectedVersion":3,"allowed":false}`))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), auth))
	w := httptest.NewRecorder()
	h.Update(w, r)
	require.Equal(t, 200, w.Code)
	require.False(t, svc.input.Allowed)
	require.Equal(t, int64(3), svc.input.ExpectedVersion)
	require.Equal(t, auth.UserID, svc.input.Actor.UserID)
	require.Equal(t, auth.TokenHash, svc.input.Actor.TokenHash)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	for _, tc := range []struct {
		err  error
		code string
	}{
		{domain.ErrEmailFactorInUse, "email_factor_in_use"}, {domain.ErrMethodNotReady, "mfa_not_ready"}, {domain.ErrPolicyConflict, "mfa_policy_conflict"},
	} {
		svc.err = tc.err
		fresh := httptest.NewRequest("POST", r.URL.String(), strings.NewReader(`{"expectedVersion":3,"allowed":false}`))
		fresh.Header.Set("Content-Type", "application/json")
		fresh = fresh.WithContext(r.Context())
		w = httptest.NewRecorder()
		h.Update(w, fresh)
		require.Equal(t, 409, w.Code)
		require.Contains(t, w.Body.String(), tc.code)
	}
}
