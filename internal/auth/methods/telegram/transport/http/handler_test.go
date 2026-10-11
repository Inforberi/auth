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

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type handlerFixture struct {
	calls        int
	failure      error
	linked       bool
	sessionToken string
}

func (f *handlerFixture) Start(context.Context, string) (*service.StartedFlow, error) {
	return &service.StartedFlow{URL: "https://oauth.telegram.org/auth?state=fixture", Binding: "binding"}, f.failure
}

func (f *handlerFixture) StartLink(context.Context, accountdomain.UserID, string, string) (*service.StartedFlow, error) {
	return &service.StartedFlow{URL: "https://oauth.telegram.org/auth", Binding: "binding"}, f.failure
}

func (f *handlerFixture) Unlink(context.Context, accountdomain.UserID, string, string) error {
	return f.failure
}

func (f *handlerFixture) Callback(_ context.Context, input service.CallbackInput) (*service.CallbackResult, error) {
	f.calls++
	f.sessionToken = input.SessionToken
	if f.linked {
		return &service.CallbackResult{Linked: true}, f.failure
	}
	return &service.CallbackResult{Session: &sessionservice.CreatedSession{RawToken: "private-session", ExpiresAt: time.Now().Add(time.Hour)}}, f.failure
}

func TestLinkCookieAndErrorContract(t *testing.T) {
	f := &handlerFixture{linked: true}
	h := New(f, zap.NewNop())
	r := httptest.NewRequest(http.MethodGet, "/callback?code=c&state=s", nil)
	r.AddCookie(&http.Cookie{Name: flowCookie, Value: "binding"})
	token := strings.Repeat("A", 43)
	r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: token})
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != 200 || f.sessionToken != token {
		t.Fatal(w.Code, f.sessionToken)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookie || cookies[0].MaxAge != -1 {
		t.Fatal("link replaced auth session", cookies)
	}
	r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: token})
	h.Callback(httptest.NewRecorder(), r)
	if f.sessionToken != "" {
		t.Fatal("ambiguous session authorized link")
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{nil, 204}, {accountdomain.ErrFreshAuthRequired, 403}, {accountdomain.ErrIdentityConflict, 409}, {accountdomain.ErrLastLoginMethod, 409},
	} {
		f.failure = tc.err
		r := httptest.NewRequest(http.MethodDelete, "/link", nil)
		r = r.WithContext(sessionhttp.SetAuthContext(r.Context(), sessionhttp.Auth{UserID: "user", TokenHash: "hash"}))
		w := httptest.NewRecorder()
		h.Unlink(w, r)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code, w.Body.String())
		}
		cookies := w.Result().Cookies()
		if tc.err == nil {
			if len(cookies) != 1 || cookies[0].Name != sessionhttp.SessionCookieName || cookies[0].MaxAge != -1 {
				t.Fatal("unlink did not clear session", cookies)
			}
		} else if len(cookies) != 0 {
			t.Fatal("failed unlink changed session cookie")
		}
	}
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
