package authjwt

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerMiddlewareAndPermissions(t *testing.T) {
	c, a, key, claims := consumerFixture(t, Strict)
	raw := signedClaims(t, key, claims)
	permission, err := RequirePermissions("orders.read")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := c.Middleware(permission(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.UserID() != claims.Subject {
			t.Error("untrusted principal")
		}
		w.WriteHeader(204)
	})))
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{name: "valid", status: 204},
		{name: "business query", mutate: func(r *http.Request) { r.URL.RawQuery = "page=1&filter=mine" }, status: 204},
		{name: "case insensitive scheme", mutate: func(r *http.Request) { r.Header.Set("Authorization", "bearer "+raw) }, status: 204},
		{name: "missing", mutate: func(r *http.Request) { r.Header.Del("Authorization") }, status: 401},
		{name: "duplicate", mutate: func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+raw) }, status: 401},
		{name: "cookie ambiguity", mutate: func(r *http.Request) { r.Header.Set("Cookie", "analytics=anything") }, status: 401},
		{name: "query token", mutate: func(r *http.Request) { r.URL.RawQuery = "access_token=" + raw }, status: 401},
		{name: "encoded query token", mutate: func(r *http.Request) { r.URL.RawQuery = "%61ccess_token=x" }, status: 401},
		{name: "bad query", mutate: func(r *http.Request) { r.URL.RawQuery = "bad=%zz" }, status: 401},
		{name: "large query", mutate: func(r *http.Request) { r.URL.RawQuery = strings.Repeat("x", 8193) }, status: 401},
		{name: "blank", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, status: 401},
		{name: "wrong scheme", mutate: func(r *http.Request) { r.SetBasicAuth("user", "secret") }, status: 401},
		{name: "spaces", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer  "+raw) }, status: 401},
		{name: "list", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+raw+",other") }, status: 401},
		{name: "oversized", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", MaxTokenBytes+1)) }, status: 401},
		{name: "invalid JWT", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer invalid") }, status: 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://orders.example/orders", nil)
			r.Header.Set("Authorization", "Bearer "+raw)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			before := calls
			online := a.onlineCalls.Load()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code, w.Body.String(), w.Header())
			}
			if tc.status != 204 && (calls != before || a.onlineCalls.Load() != online || w.Header().Get("WWW-Authenticate") == "") {
				t.Fatal("invalid request reached authority/handler")
			}
			if strings.Contains(w.Body.String(), raw) || strings.Contains(w.Body.String(), a.secret) {
				t.Fatal("credential leak")
			}
		})
	}
	denied, err := RequirePermissions("orders.write")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://orders.example/orders", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	c.Middleware(denied(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("permission bypass") }))).ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	permission(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated permission bypass") })).ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, keys := range [][]string{nil, {"orders.*"}, {"orders.read", "orders.read"}, {"a\"\r\n"}} {
		if _, err := RequirePermissions(keys...); err == nil {
			t.Fatal("invalid route policy accepted")
		}
	}
	a.mu.Lock()
	a.online.status = 503
	a.mu.Unlock()
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatal("outage fail open", w.Code)
	}
	a.mu.Lock()
	a.online.status = 429
	a.mu.Unlock()
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	ageKeys(c, MaxKeyAge)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("expired trust", w.Code)
	}
	if _, ok := PrincipalFromContext(t.Context()); ok {
		t.Fatal("principal outside authenticated request")
	}
}
