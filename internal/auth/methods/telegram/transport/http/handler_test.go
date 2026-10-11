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

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type handlerFixture struct {
	calls   int
	failure error
}

func (f *handlerFixture) Start(context.Context, string) (*service.StartedFlow, error) {
	return &service.StartedFlow{URL: "https://oauth.telegram.org/auth?state=fixture", Binding: "binding"}, f.failure
}

func (f *handlerFixture) Callback(context.Context, service.CallbackInput) (*sessionservice.CreatedSession, error) {
	f.calls++
	return &sessionservice.CreatedSession{RawToken: "private-session", ExpiresAt: time.Now().Add(time.Hour)}, f.failure
}

func TestHandlerCookiesAndErrors(t *testing.T) {
	f := &handlerFixture{}
	h := New(f, zap.NewNop())
	w := httptest.NewRecorder()
	h.Start(w, httptest.NewRequest(http.MethodPost, "/start", nil))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookie || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe flow cookie", cookies)
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{nil, 200}, {domain.ErrInvalidFlow, 400}, {domain.ErrLimited, 429}, {errors.New("dependency contains secret"), 503},
	} {
		f.failure = tc.err
		r := httptest.NewRequest(http.MethodGet, "/callback?code=code&state=state", nil)
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		h.Callback(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "private-session") || strings.Contains(w.Body.String(), "dependency contains secret") {
			t.Fatal(w.Code, w.Body.String())
		}
		if tc.err != nil && len(w.Result().Cookies()) != 0 {
			t.Fatal("failed callback modified cookie")
		}
		if tc.err == nil {
			var session, cleared bool
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == sessionhttp.SessionCookieName && cookie.Secure && cookie.HttpOnly {
					session = true
				}
				if cookie.Name == flowCookie && cookie.MaxAge == -1 {
					cleared = true
				}
			}
			if !session || !cleared {
				t.Fatal("success cookie contract missing")
			}
		}
	}
	before := f.calls
	for _, endpoint := range []string{"/callback?code=a&code=b&state=s", "/callback?code=a&state=s&error=denied", "/callback?code=a&state=%zz"} {
		r := httptest.NewRequest(http.MethodGet, endpoint, nil)
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		h.Callback(w, r)
		if w.Code != 400 {
			t.Fatal("malformed query accepted")
		}
	}
	if f.calls != before {
		t.Fatal("malformed callback reached service")
	}
	r := httptest.NewRequest(http.MethodGet, "/callback?code=c&state=s", nil)
	r.AddCookie(cookies[0])
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != 400 || f.calls != before {
		t.Fatal("ambiguous cookies accepted")
	}
}
