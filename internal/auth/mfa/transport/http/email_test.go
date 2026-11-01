package mfahttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type emailHTTPFixture struct {
	calls int
	proof service.Proof
	input service.CompleteLoginInput
	err   error
}

func (f *emailHTTPFixture) Request(_ context.Context, proof service.Proof, _, _ string) (*otpservice.RequestedCode, error) {
	f.calls++
	f.proof = proof
	return &otpservice.RequestedCode{Binding: "preparation-binding", ExpiresAt: time.Now().Add(time.Minute)}, f.err
}

func (f *emailHTTPFixture) Confirm(_ context.Context, input otpservice.EmailPreparationConfirmation) (*otpservice.ReauthenticatedSession, error) {
	f.calls++
	f.proof = input.Proof
	return &otpservice.ReauthenticatedSession{Token: "rotated-session", ExpiresAt: time.Now().Add(time.Hour)}, f.err
}

func (f *emailHTTPFixture) Status(_ context.Context, proof service.Proof) (*domain.EmailFactor, error) {
	f.calls++
	f.proof = proof
	return &domain.EmailFactor{Allowed: true, Configured: true, Usable: true}, f.err
}

func (f *emailHTTPFixture) Enable(_ context.Context, proof service.Proof) error {
	f.calls++
	f.proof = proof
	return f.err
}

func (f *emailHTTPFixture) Disable(ctx context.Context, proof service.Proof) error {
	return f.Enable(ctx, proof)
}

func (f *emailHTTPFixture) Authenticate(context.Context, passwordservice.LoginInput) (service.PrimaryProof, error) {
	f.calls++
	return service.PrimaryProof{UserID: "11111111-1111-4111-8111-111111111111", Method: "password", AuthVersion: 2, Reference: "server-verified-hash", VerifiedAt: time.Now()}, f.err
}

func (f *emailHTTPFixture) Start(context.Context, service.PrimaryProof, string) (*service.LoginChallenge, error) {
	f.calls++
	return &service.LoginChallenge{Token: "public-challenge", Binding: "private-browser-binding", ExpiresAt: time.Now().Add(time.Minute)}, f.err
}

func (f *emailHTTPFixture) Complete(_ context.Context, input service.CompleteLoginInput) (*service.LoginSession, error) {
	f.calls++
	f.input = input
	return &service.LoginSession{Token: "new-session", ExpiresAt: time.Now().Add(time.Hour)}, f.err
}

func emailHTTPAuth() sessionhttp.Auth {
	return sessionhttp.Auth{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 2}
}

func TestEmailMFAProjectCookieIsolation(t *testing.T) {
	f := &emailHTTPFixture{}
	name := EmailLoginCookie + "-project-a"
	h, err := NewEmailWithCookie(f, f, f, f, zap.NewNop(), name)
	require.NoError(t, err)
	for _, invalid := range []string{"mfa-email", "__Host-invalid;name", "__Host-invalid\r\n"} {
		_, err := NewEmailWithCookie(f, f, f, f, zap.NewNop(), invalid)
		require.Error(t, err)
	}
	w := httptest.NewRecorder()
	h.StartEmailLogin(w, emailHTTPRequest(`{"email":"user@example.test","password":"secret"}`, false))
	require.Equal(t, 202, w.Code)
	cookies := w.Result().Cookies()
	require.Equal(t, name, cookies[len(cookies)-1].Name)
	request := emailHTTPRequest(`{"challenge":"challenge","code":"12345678"}`, false)
	request.AddCookie(&http.Cookie{Name: EmailLoginCookie, Value: "foreign-binding"})
	w = httptest.NewRecorder()
	before := f.calls
	h.CompleteEmailLogin(w, request)
	require.Equal(t, 400, w.Code)
	require.Equal(t, before, f.calls)
	request = emailHTTPRequest(`{"challenge":"challenge","code":"12345678"}`, false)
	request.AddCookie(&http.Cookie{Name: EmailLoginCookie, Value: "foreign-binding"})
	request.AddCookie(&http.Cookie{Name: name, Value: "own-binding"})
	w = httptest.NewRecorder()
	h.CompleteEmailLogin(w, request)
	require.Equal(t, 200, w.Code)
	require.Equal(t, "own-binding", f.input.Binding)
	require.Equal(t, name, w.Result().Cookies()[0].Name)
	require.Negative(t, w.Result().Cookies()[0].MaxAge)
}

func emailHTTPRequest(body string, auth bool) *http.Request {
	r := httptest.NewRequest("POST", "https://auth.example/test", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://ui.example")
	if auth {
		r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), emailHTTPAuth()))
	}
	return r
}

func TestEmailMFAHTTPBindingAndCookies(t *testing.T) {
	f := &emailHTTPFixture{}
	h, err := NewEmail(f, f, f, f, zap.NewNop())
	require.NoError(t, err)
	_, err = NewEmail(nil, f, f, f, zap.NewNop())
	require.ErrorIs(t, err, domain.ErrUnavailable)
	w := httptest.NewRecorder()
	h.StartEmailLogin(w, emailHTTPRequest(`{"email":"user@example.test","password":"secret"}`, false))
	require.Equal(t, 202, w.Code)
	require.NotContains(t, w.Body.String(), "private-browser-binding")
	require.NotContains(t, w.Body.String(), "new-session")
	var binding *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == EmailLoginCookie {
			binding = cookie
		}
	}
	require.NotNil(t, binding)
	require.True(t, binding.Secure && binding.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, binding.SameSite)
	require.Equal(t, "/", binding.Path)
	require.Empty(t, binding.Domain)
	for _, cookies := range [][]*http.Cookie{nil, {binding, binding}} {
		r := emailHTTPRequest(`{"challenge":"challenge","code":"12345678"}`, false)
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		before := f.calls
		w = httptest.NewRecorder()
		h.CompleteEmailLogin(w, r)
		require.Equal(t, 400, w.Code)
		require.Equal(t, before, f.calls)
		require.Empty(t, w.Result().Cookies())
	}
	r := emailHTTPRequest(`{"challenge":"challenge","code":"12345678","binding":"json-binding"}`, false)
	r.AddCookie(binding)
	w = httptest.NewRecorder()
	h.CompleteEmailLogin(w, r)
	require.Equal(t, 400, w.Code)
	r = emailHTTPRequest(`{"challenge":"challenge","code":"12345678"}`, false)
	r.AddCookie(binding)
	w = httptest.NewRecorder()
	h.CompleteEmailLogin(w, r)
	require.Equal(t, 200, w.Code)
	require.Equal(t, binding.Value, f.input.Binding)
	require.False(t, f.input.Recovery)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.NotContains(t, w.Body.String(), "new-session")
}

func TestEmailMFAHTTPOwnerAndOrigin(t *testing.T) {
	f := &emailHTTPFixture{}
	h, err := NewEmail(f, f, f, f, zap.NewNop())
	require.NoError(t, err)
	for _, handler := range []http.HandlerFunc{h.ReadEmailFactor, h.EnableEmailFactor, h.DisableEmailFactor, h.RequestEmailPreparation, h.ConfirmEmailPreparation} {
		w := httptest.NewRecorder()
		handler(w, emailHTTPRequest(`{}`, false))
		require.Equal(t, 401, w.Code)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
	require.Zero(t, f.calls)
	for _, handler := range []http.HandlerFunc{h.StartEmailLogin, h.CompleteEmailLogin, h.EnableEmailFactor, h.DisableEmailFactor, h.RequestEmailPreparation, h.ConfirmEmailPreparation} {
		protected := middleware.RequireOrigin(middleware.OriginConfig{AllowedOrigins: []string{"https://ui.example"}})(handler)
		r := emailHTTPRequest(`{}`, true)
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		require.Equal(t, 403, w.Code)
		require.Empty(t, w.Result().Cookies())
	}
	require.Zero(t, f.calls)
	w := httptest.NewRecorder()
	h.EnableEmailFactor(w, emailHTTPRequest(`{"userId":"another-user"}`, true))
	require.Equal(t, 400, w.Code)
	require.Zero(t, f.calls)
	w = httptest.NewRecorder()
	h.EnableEmailFactor(w, emailHTTPRequest(`{}`, true))
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, w.Result().Cookies())
	require.Equal(t, -1, w.Result().Cookies()[0].MaxAge)
	require.Equal(t, emailHTTPAuth().UserID, f.proof.UserID)
	require.Equal(t, emailHTTPAuth().TokenHash, f.proof.TokenHash)
	f.err = domain.ErrRequiredByPolicy
	w = httptest.NewRecorder()
	h.DisableEmailFactor(w, emailHTTPRequest(`{}`, true))
	require.Equal(t, 403, w.Code)
	require.Empty(t, w.Result().Cookies())
	require.Contains(t, w.Body.String(), "mfa_required_by_policy")
}
