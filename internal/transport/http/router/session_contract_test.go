package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type managementFault struct {
	err      error
	calls    int
	hash, id string
}

func TestSessionMetadataIsNotCredential(t *testing.T) {
	for _, path := range []string{"/me", "/sessions"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/auth"+path, nil)
		r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: "valid"})
		New(contractHandlers("dev")).ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), "hash") || strings.Contains(w.Body.String(), "valid") {
			t.Fatal("metadata exposed credential", w.Body.String())
		}
		if path == "/me" {
			var response sessionhttp.MeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.UserID != "user-1" || response.SessionID != currentSessionID {
				t.Fatal("me contract", response, err)
			}
		} else {
			var response sessionhttp.SessionsResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Sessions) != 1 || !response.Sessions[0].Current || response.Sessions[0].ID != currentSessionID {
				t.Fatal("current session metadata", response, err)
			}
		}
	}
}

func (s *managementFault) List(context.Context, accountdomain.UserID, string, string) (*sessionservice.SessionPage, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &sessionservice.SessionPage{Sessions: []sessiondomain.Session{}}, nil
}

func (s *managementFault) Revoke(_ context.Context, user accountdomain.UserID, hash, id string) error {
	s.calls++
	s.hash = hash
	s.id = id
	if user != "user-1" {
		panic("ownership lost")
	}
	return s.err
}

func (s *managementFault) LogoutAll(_ context.Context, user accountdomain.UserID, hash string) error {
	s.calls++
	s.hash = hash
	if user != "user-1" {
		panic("ownership lost")
	}
	return s.err
}

func TestSessionManagementRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, token, origin string
		err                               error
		status                            int
		clear                             bool
		calls                             int
	}{
		{"me", "GET", "/me", "valid", "", nil, 200, false, 0},
		{"me unauthorized", "GET", "/me", "", "", nil, 401, false, 0},
		{"list", "GET", "/sessions", "valid", "", nil, 200, false, 1},
		{"list dependency", "GET", "/sessions", "valid", "", errors.New("private DSN"), 503, false, 1},
		{"logout", "POST", "/logout", "valid", "https://localhost:8443", nil, 204, true, 1},
		{"logout missing cookie", "POST", "/logout", "", "https://localhost:8443", nil, 401, true, 0},
		{"logout stale cookie", "POST", "/logout", "expired", "https://localhost:8443", nil, 401, true, 0},
		{"logout missing origin", "POST", "/logout", "valid", "", nil, 403, false, 0},
		{"logout foreign origin", "POST", "/logout", "valid", "https://evil.test", nil, 403, false, 0},
		{"logout dependency", "POST", "/logout", "valid", "https://localhost:8443", errors.New("private token"), 503, false, 1},
		{"logout raced revocation", "POST", "/logout", "valid", "https://localhost:8443", sessiondomain.ErrSessionNotFound, 401, true, 1},
		{"logout-all", "POST", "/logout-all", "valid", "https://localhost:8443", nil, 204, true, 1},
		{"logout-all missing origin", "POST", "/logout-all", "valid", "", nil, 403, false, 0},
		{"revoke current", "DELETE", "/sessions/" + currentSessionID, "valid", "https://localhost:8443", nil, 204, true, 1},
		{"revoke other", "DELETE", "/sessions/22222222-2222-4222-8222-222222222222", "valid", "https://localhost:8443", nil, 204, false, 1},
		{"foreign or unknown", "DELETE", "/sessions/22222222-2222-4222-8222-222222222222", "valid", "https://localhost:8443", sessiondomain.ErrOwnedSessionNotFound, 404, false, 1},
		{"invalid ID", "DELETE", "/sessions/bad", "valid", "https://localhost:8443", sessiondomain.ErrInvalidSessionID, 400, false, 1},
		{"revoke missing origin", "DELETE", "/sessions/" + currentSessionID, "valid", "", nil, 403, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := contractHandlers("dev")
			stub := &managementFault{err: tc.err}
			h.Session = sessionhttp.NewHandler(stub, zap.NewNop())
			r := httptest.NewRequest(tc.method, "/api/v1/auth"+tc.path, nil)
			if tc.token != "" {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: tc.token})
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != tc.status || stub.calls != tc.calls {
				t.Fatal(w.Code, w.Body.String(), stub.calls)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("private response cacheable")
			}
			if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "hash") || strings.Contains(w.Body.String(), "valid") && tc.status == 200 {
				t.Fatal("secret disclosed")
			}
			cookies := w.Result().Cookies()
			if tc.clear {
				if len(cookies) != 1 || cookies[0].Value != "" || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" {
					t.Fatal("cookie cleanup failed")
				}
			} else if len(cookies) != 0 {
				t.Fatal("failure or another-session revoke cleared cookie")
			}
			if stub.hash != "" && stub.hash != "hash" {
				t.Fatal("raw token passed to management")
			}
			if tc.method == "DELETE" && tc.calls == 1 && stub.id != strings.TrimPrefix(tc.path, "/sessions/") {
				t.Fatal("wrong path ID")
			}
			if tc.status == 204 && w.Body.Len() != 0 {
				t.Fatal("204 response has body")
			}
		})
	}
}
