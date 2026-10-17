package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type contractExchange struct {
	calls int
	input tokenservice.ExchangeInput
	err   error
}

func (s *contractExchange) Exchange(_ context.Context, input tokenservice.ExchangeInput) (*tokenservice.ExchangeResult, error) {
	s.calls++
	s.input = input
	if s.err != nil {
		return nil, s.err
	}
	return &tokenservice.ExchangeResult{
		SignedToken: &signing.SignedToken{Raw: "synthetic-access-token", ExpiresAt: time.Now().Add(time.Minute)},
		Audience:    input.Audience, Scope: []accessdomain.PermissionKey{"orders.read"},
	}, nil
}

func TestTokenExchangeContracts(t *testing.T) {
	for _, mode := range []string{"valid", "origin", "missing origin", "duplicate origin", "session", "disabled", "no handler", "shape", "duplicate field", "case alias", "null", "oversized", "unknown field", "bearer", "forbidden", "limited", "mfa", "verification", "unavailable", "busy", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			s := &contractExchange{}
			h := contractHandlers("prod")
			h.Config.Browser.AllowedOrigins = []string{"https://app.example.com"}
			sessions := &securitySessions{}
			h.Middleware = sessionhttp.New(sessions, zap.NewNop())
			h.Config.JWT.Enabled = true
			h.Tokens = tokenhttp.New(s, []byte(`{"keys":[]}`), zap.NewNop())
			body := `{"audience":"orders","scope":["orders.read"]}`
			want := 200
			switch mode {
			case "origin", "missing origin", "duplicate origin":
				want = 403
			case "session":
				want = 401
			case "disabled":
				h.Config.JWT.Enabled = false
				want = 404
			case "no handler":
				h.Tokens = nil
				want = 404
			case "shape":
				body = `[]`
				want = 400
			case "duplicate field":
				body = `{"audience":"orders","audience":"other","scope":["orders.read"]}`
				want = 400
			case "case alias":
				body = `{"Audience":"orders","scope":["orders.read"]}`
				want = 400
			case "null":
				body = `{"audience":"orders","scope":null}`
				want = 400
			case "oversized":
				body = strings.Repeat(" ", 8193) + body
				want = 400
			case "unknown field":
				body = `{"audience":"orders","scope":["orders.read"],"mode":"local"}`
				want = 400
			case "bearer":
				want = 400
			case "forbidden":
				s.err = tokendomain.ErrForbidden
				want = 403
			case "limited":
				s.err = tokendomain.ErrRateLimited
				want = 429
			case "mfa":
				s.err = sessiondomain.ErrMFARequired
				want = 403
			case "verification":
				s.err = accountdomain.ErrEmailUnverified
				want = 403
			case "unavailable":
				s.err = errors.New("synthetic secret must never be returned")
				want = 503
			case "busy":
				s.err = authjwt.ErrBusy
				want = 503
			case "revoked":
				s.err = sessiondomain.ErrSessionNotFound
				want = 401
			}
			req := httptest.NewRequest("POST", "https://auth.example/api/v1/auth/token/exchange", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://app.example.com")
			req.AddCookie(&http.Cookie{Name: "__Host-session", Value: validCookieToken})
			switch mode {
			case "origin":
				req.Header.Set("Origin", "https://evil.example")
			case "missing origin":
				req.Header.Del("Origin")
			case "duplicate origin":
				req.Header.Add("Origin", "https://app.example.com")
			case "session":
				req.Header.Del("Cookie")
			case "bearer":
				req.Header.Set("Authorization", "Bearer stolen")
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, req)
			if w.Code != want {
				t.Fatal(mode, w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || sessions.refresh != 0 {
				t.Fatal("exchange modified session/cache", w.Header(), sessions)
			}
			if strings.Contains(w.Body.String(), "synthetic secret") {
				t.Fatal("dependency error leaked")
			}
			if want == 200 {
				var result tokenhttp.ExchangeResponse
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.AccessToken != "synthetic-access-token" || result.TokenType != "Bearer" || result.ExpiresIn <= 0 || result.Audience != "orders" || result.Scope != "orders.read" {
					t.Fatal(result, err)
				}
				if s.input.SessionID != currentSessionID || s.input.Actor.UserID == "" || s.input.Actor.TokenHash == "" || s.input.IP == "" {
					t.Fatal("missing trusted context", s.input)
				}
			}
			if want == 429 && w.Header().Get("Retry-After") != "60" {
				t.Fatal("missing retry budget")
			}
			if (want == 400 || want == 404 || mode == "origin" || mode == "missing origin" || mode == "duplicate origin" || mode == "session") && s.calls != 0 {
				t.Fatal("invalid request reached issuance")
			}
		})
	}
}

func TestJWKSContracts(t *testing.T) {
	h := contractHandlers("prod")
	h.Config.JWT.Enabled = true
	public := []byte(`{"keys":[{"kid":"synthetic-public-only"}]}`)
	h.Tokens = tokenhttp.New(&contractExchange{}, public, zap.NewNop())
	r := New(h)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example/.well-known/jwks.json", nil))
	if w.Code != 200 || w.Body.String() != string(public) || w.Header().Get("Set-Cookie") != "" || w.Header().Get("ETag") == "" || !strings.Contains(w.Header().Get("Cache-Control"), "max-age=30") {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
	for _, method := range []string{"HEAD", "GET"} {
		req := httptest.NewRequest(method, "https://auth.example/.well-known/jwks.json", nil)
		want := 200
		if method == "GET" {
			req.Header.Set("If-None-Match", w.Header().Get("ETag"))
			want = 304
		}
		next := httptest.NewRecorder()
		r.ServeHTTP(next, req)
		if next.Code != want || next.Body.Len() != 0 {
			t.Fatal(next.Code, next.Body.String())
		}
	}
	h.Config.JWT.Enabled = false
	w = httptest.NewRecorder()
	New(h).ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example/.well-known/jwks.json", nil))
	if w.Code != 404 {
		t.Fatal("disabled JWKS published", w.Code)
	}
	doc := readAPI(t)
	for _, path := range []string{"/api/v1/auth/token/exchange", "/.well-known/jwks.json"} {
		if len(doc.Paths[path]) == 0 {
			t.Fatal("Swagger route missing", path)
		}
	}
}
