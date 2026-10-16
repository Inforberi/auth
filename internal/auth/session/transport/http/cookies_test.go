package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestMalformedCookieNeverReachesSessionStorage(t *testing.T) {
	for _, token := range []string{"", "bad", strings.Repeat("A", 44), strings.Repeat("A", 42) + "B", strings.Repeat("!", 43)} {
		service := &sessionStub{}
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		w := httptest.NewRecorder()
		New(service, zap.NewNop()).Auth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("malformed cookie accepted") })).ServeHTTP(w, r)
		if w.Code != 401 || service.calls != 0 {
			t.Fatal("malformed cookie reached SQL", w.Code, service.calls)
		}
	}
}

func TestAmbiguousSessionCookieNeverReachesStorage(t *testing.T) {
	valid := SessionCookieName + "=" + validCookieToken
	for _, headers := range [][]string{
		{valid + "; " + valid},
		{valid, valid},
		{valid + "; " + SessionCookieName + "=bad"},
		{SessionCookieName + "=bad; " + valid},
		{valid + "; " + SessionCookieName + "=\"unterminated"},
		{SessionCookieName + "=\"unterminated", valid},
		{valid + "; " + SessionCookieName},
		{valid + "; " + SessionCookieName + " =bad"},
	} {
		for _, mode := range []string{"auth", "no-refresh", "logout"} {
			t.Run(mode+strings.Join(headers, "|"), func(t *testing.T) {
				svc := &sessionStub{}
				m := New(svc, zap.NewNop())
				guard := m.Auth
				if mode == "no-refresh" {
					guard = m.NoRefreshAuth
				}
				if mode == "logout" {
					guard = m.LogoutAuth
				}
				r := httptest.NewRequest("POST", "/", nil)
				for _, header := range headers {
					r.Header.Add("Cookie", header)
				}
				w := httptest.NewRecorder()
				guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("ambiguous cookie accepted") })).ServeHTTP(w, r)
				if w.Code != 401 || svc.calls != 0 {
					t.Fatal("ambiguous cookie reached storage", w.Code, svc.calls)
				}
				cookies := w.Result().Cookies()
				if mode != "logout" && len(cookies) != 0 {
					t.Fatal("authentication failure changed cookie")
				}
				if mode == "logout" && (len(cookies) != 1 || cookies[0].MaxAge != -1) {
					t.Fatal("logout cleanup changed")
				}
			})
		}
	}
}

func TestUnambiguousSessionCookie(t *testing.T) {
	for _, headers := range [][]string{
		{SessionCookieName + "=" + validCookieToken},
		{"theme=dark", SessionCookieName + "=" + validCookieToken},
		{"theme=dark; " + SessionCookieName + "=\"" + validCookieToken + "\"; other=value"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		for _, header := range headers {
			r.Header.Add("Cookie", header)
		}
		if token, err := GetSessionCookie(r); err != nil || token != validCookieToken {
			t.Fatal(token, err)
		}
	}
}
