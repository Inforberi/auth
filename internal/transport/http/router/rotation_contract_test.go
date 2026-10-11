package router

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
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type rotationContract struct {
	err   error
	calls int
}

func (s *rotationContract) Rotate(_ context.Context, user accountdomain.UserID, hash string) (*service.CreatedSession, error) {
	s.calls++
	if user != "user-1" || hash != "hash" {
		panic("caller not forwarded")
	}
	return &service.CreatedSession{RawToken: strings.Repeat("B", 42) + "A", ExpiresAt: time.Now().Add(time.Hour)}, s.err
}

func TestRotationHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, method, origin string
		cookie               bool
		err                  error
		status, calls        int
	}{
		{"success", "POST", "https://localhost:8443", true, nil, 204, 1},
		{"no origin", "POST", "", true, nil, 403, 0},
		{"wrong origin", "POST", "https://attacker.example", true, nil, 403, 0},
		{"no session", "POST", "https://localhost:8443", false, nil, 401, 0},
		{"already rotated", "POST", "https://localhost:8443", true, domain.ErrSessionNotFound, 401, 1},
		{"SQL failure", "POST", "https://localhost:8443", true, errors.New("private SQL secret"), 503, 1},
		{"GET", "GET", "https://localhost:8443", true, nil, 405, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &rotationContract{err: tc.err}
			h := contractHandlers("prod")
			h.Rotation = sessionhttp.NewRotation(s, zap.NewNop())
			r := httptest.NewRequest(tc.method, "/api/v1/auth/session/rotate", nil)
			r.Header.Set("Origin", tc.origin)
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: validCookieToken})
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != tc.status || s.calls != tc.calls || strings.Contains(w.Body.String(), "secret") {
				t.Fatal(w.Code, s.calls, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if tc.status == 204 {
				if len(cookies) != 1 || cookies[0].Value == validCookieToken || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteLaxMode || w.Body.Len() != 0 {
					t.Fatal("rotation cookie contract", cookies, w.Body.String())
				}
			} else if len(cookies) != 0 {
				t.Fatal("failed rotation changed cookies", cookies)
			}
			if tc.method == "POST" && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("rotation response can be cached")
			}
		})
	}
}
