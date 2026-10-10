package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireOrigin(t *testing.T) {
	cfg := OriginConfig{AllowedOrigins: []string{"https://app.example.com"}}
	for _, tc := range []struct {
		name    string
		origins []string
		allowed bool
	}{
		{"exact", []string{"https://app.example.com"}, true},
		{"missing", nil, false},
		{"null", []string{"null"}, false},
		{"foreign", []string{"https://evil.example.com"}, false},
		{"suffix", []string{"https://app.example.com.evil.test"}, false},
		{"path", []string{"https://app.example.com/"}, false},
		{"multiple", []string{"https://app.example.com", "https://evil.example.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := RequireOrigin(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) }))
			r := httptest.NewRequest(http.MethodPost, "https://evil.example.com/logout", nil)
			r.Header["Origin"] = tc.origins
			r.Header.Set("X-Forwarded-Host", "app.example.com")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if called != tc.allowed {
				t.Fatal("origin gate bypassed or rejected trusted origin")
			}
			if !tc.allowed && w.Code != 403 {
				t.Fatal(w.Code)
			}
		})
	}
}

func TestOriginConfiguration(t *testing.T) {
	for _, origin := range []string{"", "null", "*", "http://localhost:8080", "https://user@example.com", "https://example.com/", "https://example.com?", "https://example.com#fragment"} {
		if (OriginConfig{AllowedOrigins: []string{origin}}).Validate() == nil {
			t.Fatalf("accepted %q", origin)
		}
	}
	if (OriginConfig{}).Validate() == nil {
		t.Fatal("missing configuration accepted")
	}
}
