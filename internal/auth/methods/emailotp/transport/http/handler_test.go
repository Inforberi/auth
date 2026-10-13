package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type httpFixture struct {
	err     error
	calls   int
	binding string
}

func (f *httpFixture) RequestReauthentication(ctx context.Context, _ mfaservice.Proof, email, ip string) (*service.RequestedCode, error) {
	return f.Request(ctx, email, ip)
}

func (f *httpFixture) ConfirmReauthentication(_ context.Context, input service.ReauthenticationInput) (*service.ReauthenticatedSession, error) {
	f.calls++
	f.binding = input.Binding
	if f.err != nil {
		return nil, f.err
	}
	return &service.ReauthenticatedSession{Token: strings.Repeat("A", 43), VerifiedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (f *httpFixture) Request(context.Context, string, string) (*service.RequestedCode, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &service.RequestedCode{Binding: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (f *httpFixture) Confirm(_ context.Context, p service.ConfirmInput) (*sessionservice.CreatedSession, error) {
	f.calls++
	f.binding = p.Binding
	if f.err != nil {
		return nil, f.err
	}
	if p.Binding == "" {
		return nil, domain.ErrInvalidCode
	}
	return &sessionservice.CreatedSession{RawToken: strings.Repeat("A", 43), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestRequestAndConfirmCookies(t *testing.T) {
	f := &httpFixture{}
	h := New(f, zap.NewNop())
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"user@example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Request(w, r)
	cookies := w.Result().Cookies()
	if w.Code != 202 || len(cookies) != 1 || cookies[0].Name != flowCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" {
		t.Fatal(w.Code, w.Body.String(), cookies)
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader(`{"code":"12345678"}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.Confirm(w, r)
	cookies = w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 2 || cookies[0].MaxAge != -1 || cookies[1].Name != sessionhttp.SessionCookieName || strings.Contains(w.Body.String(), strings.Repeat("A", 43)) {
		t.Fatal(w.Code, w.Body.String(), cookies)
	}
}

func TestConfirmRejectsMissingOrDuplicateBinding(t *testing.T) {
	for _, count := range []int{0, 2} {
		f := &httpFixture{}
		h := New(f, zap.NewNop())
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"code":"12345678"}`))
		r.Header.Set("Content-Type", "application/json")
		for range count {
			r.AddCookie(&http.Cookie{Name: flowCookie, Value: strings.Repeat("A", 43)})
		}
		w := httptest.NewRecorder()
		h.Confirm(w, r)
		if w.Code != 400 || f.binding != "" || len(w.Result().Cookies()) != 0 {
			t.Fatal(count, w.Code, w.Body.String())
		}
	}
}

func TestErrorsDoNotSetSession(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{domain.ErrInvalidCode, 400, "invalid_email_login"},
		{domain.ErrLimited, 429, "rate_limited"},
		{domain.ErrDisabled, 404, "method_disabled"},
		{errors.New("private SQL detail"), 503, "temporarily_unavailable"},
	} {
		f := &httpFixture{err: tc.err}
		h := New(f, zap.NewNop())
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"code":"12345678"}`))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: flowCookie, Value: strings.Repeat("A", 43)})
		w := httptest.NewRecorder()
		h.Confirm(w, r)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) || strings.Contains(w.Body.String(), "private") || len(w.Result().Cookies()) != 0 {
			t.Fatal(tc, w.Code, w.Body.String())
		}
	}
}

func TestInvalidJSONBeforeService(t *testing.T) {
	f := &httpFixture{}
	h := New(f, zap.NewNop())
	for _, handler := range []http.HandlerFunc{h.Request, h.Confirm} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"unknown":true}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 400 || f.calls != 0 {
			t.Fatal("invalid body reached service")
		}
	}
}
