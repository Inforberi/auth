package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

type introspectionContract struct {
	authenticated, inspected int
	err                      error
}

func (s *introspectionContract) Authenticate(id, secret string) (*service.IntrospectionClient, bool) {
	s.authenticated++
	return &service.IntrospectionClient{}, id == "orders" && secret == "synthetic"
}

func (s *introspectionContract) Inspect(context.Context, *service.IntrospectionClient, string) (service.IntrospectionResult, error) {
	s.inspected++
	return service.IntrospectionResult{}, s.err
}

func TestIntrospectionServiceTransport(t *testing.T) {
	const path = "/api/v1/internal/auth/token/introspect"
	for _, tc := range []struct {
		name, body            string
		mutate                func(*http.Request)
		err                   error
		status, auth, inspect int
	}{
		{name: "inactive", body: `{"token":"invalid"}`, status: 200, auth: 1, inspect: 1},
		{name: "no credentials", body: `not JSON`, mutate: func(r *http.Request) { r.Header.Del("Authorization") }, status: 401},
		{name: "wrong credentials", body: `not JSON`, mutate: func(r *http.Request) { r.SetBasicAuth("orders", "wrong") }, status: 401, auth: 1},
		{name: "bearer", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") }, status: 401},
		{name: "duplicate auth", mutate: func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }, status: 401},
		{name: "oversized auth", mutate: func(r *http.Request) { r.Header.Set("Authorization", strings.Repeat("x", 257)) }, status: 401},
		{name: "origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://example.com") }, status: 403},
		{name: "cookie", mutate: func(r *http.Request) { r.Header.Set("Cookie", "session=synthetic") }, status: 403},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "token=synthetic" }, status: 403},
		{name: "preflight", mutate: func(r *http.Request) { r.Method = "OPTIONS"; r.Header.Set("Origin", "https://example.com") }, status: 403},
		{name: "unknown field", body: `{"token":"x","sub":"y"}`, status: 400, auth: 1},
		{name: "duplicate field", body: `{"token":"x","token":"y"}`, status: 400, auth: 1},
		{name: "case alias", body: `{"Token":"x"}`, status: 400, auth: 1},
		{name: "null", body: `{"token":null}`, status: 400, auth: 1},
		{name: "trailing", body: `{"token":"x"} {}`, status: 400, auth: 1},
		{name: "oversized", body: strings.Repeat("x", 8193), status: 400, auth: 1},
		{name: "audience denied", body: `{"token":"x"}`, err: domain.ErrForbidden, status: 403, auth: 1, inspect: 1},
		{name: "limited", body: `{"token":"x"}`, err: domain.ErrRateLimited, status: 429, auth: 1, inspect: 1},
		{name: "dependency", body: `{"token":"x"}`, err: errors.New("private synthetic dependency"), status: 503, auth: 1, inspect: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &introspectionContract{err: tc.err}
			h := contractHandlers("prod")
			h.Config.JWT.Enabled = true
			h.Introspection = tokenhttp.NewIntrospection(s)
			r := httptest.NewRequest("POST", path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.SetBasicAuth("orders", "synthetic")
			if tc.mutate != nil {
				tc.mutate(r)
			}
			w := httptest.NewRecorder()
			New(h).ServeHTTP(w, r)
			if w.Code != tc.status || s.authenticated != tc.auth || s.inspected != tc.inspect {
				t.Fatal(w.Code, w.Body.String(), s)
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unsafe response", w.Header())
			}
			if strings.Contains(w.Body.String(), "private synthetic") {
				t.Fatal("dependency leaked")
			}
			if tc.status == 200 && strings.TrimSpace(w.Body.String()) != `{"active":false}` {
				t.Fatal("inactive PII", w.Body.String())
			}
			if tc.status == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing challenge")
			}
		})
	}
	for _, enabled := range []bool{false, true} {
		h := contractHandlers("prod")
		h.Config.JWT.Enabled = enabled
		if !enabled {
			h.Introspection = tokenhttp.NewIntrospection(&introspectionContract{})
		}
		w := httptest.NewRecorder()
		New(h).ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Fatal("disabled route exposed", w.Code)
		}
	}
}
