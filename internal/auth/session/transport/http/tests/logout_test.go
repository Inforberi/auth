package http_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestLogoutAuthCookiePolicy(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		clear  bool
	}{
		{domain.ErrSessionNotFound, 401, true},
		{domain.ErrSessionExpired, 401, true},
		{errors.New("SQL unavailable"), 503, false},
	} {
		r := httptest.NewRequest(http.MethodPost, "/logout", nil)
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("rejected session reached logout") })
		sessionhttp.New(&sessionStub{err: tc.err}, zap.NewNop()).LogoutAuth(next).ServeHTTP(w, r)
		if w.Code != tc.status || (len(w.Result().Cookies()) != 0) != tc.clear {
			t.Fatal("logout cookie policy", w.Code)
		}
	}
}
