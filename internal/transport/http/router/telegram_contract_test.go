package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type contractTelegram struct{ starts, callbacks int }

func (f *contractTelegram) Start(context.Context, string) (*service.StartedFlow, error) {
	f.starts++
	return &service.StartedFlow{URL: "https://oauth.telegram.org/auth", Binding: validCookieToken}, nil
}

func TestTelegramLinkRoutesRequireOriginAndSession(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, tc := range []struct {
			origin  string
			session bool
			status  int
		}{
			{"", true, 403}, {"https://evil.test", true, 403}, {"https://localhost:8443", false, 401}, {"https://localhost:8443", true, 200},
		} {
			r := httptest.NewRequest(method, "/api/v1/auth/telegram/link", nil)
			r.Header.Set("Origin", tc.origin)
			if tc.session {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
			}
			w := httptest.NewRecorder()
			New(contractHandlers("test")).ServeHTTP(w, r)
			want := tc.status
			if method == http.MethodDelete && want == 200 {
				want = 204
			}
			if w.Code != want {
				t.Fatal(method, tc, w.Code, w.Body.String())
			}
		}
	}
}

func (f *contractTelegram) StartLink(context.Context, accountdomain.UserID, string, string) (*service.StartedFlow, error) {
	return &service.StartedFlow{URL: "https://oauth.telegram.org/auth", Binding: validCookieToken}, nil
}

func (f *contractTelegram) Unlink(context.Context, accountdomain.UserID, string, string) error {
	return nil
}

func (f *contractTelegram) Callback(context.Context, service.CallbackInput) (*service.CallbackResult, error) {
	f.callbacks++
	return &service.CallbackResult{Session: &sessionservice.CreatedSession{RawToken: validCookieToken, ExpiresAt: time.Now().Add(time.Hour)}}, nil
}

func TestTelegramOriginAndDisabledRoutes(t *testing.T) {
	h := contractHandlers("test")
	for _, enabled := range []bool{false, true} {
		h.Config.Telegram.Enabled = enabled
		for _, origin := range []string{"", "https://evil.test", "https://localhost:8443"} {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/telegram/start", nil)
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			want := 403
			if origin == "https://localhost:8443" {
				want = 404
				if enabled {
					want = 200
				}
			}
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" || (want != 200 && len(w.Result().Cookies()) != 0) {
				t.Fatal(enabled, origin, w.Code, w.Body.String())
			}
		}
		r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/telegram/callback?code=c&state=s", nil)
		r.AddCookie(&http.Cookie{Name: "__Host-telegram-flow", Value: validCookieToken})
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, r)
		want := 404
		if enabled {
			want = 200
		}
		if w.Code != want {
			t.Fatal("callback route policy", enabled, w.Code)
		}
	}
}
