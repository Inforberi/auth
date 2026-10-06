package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		valid                   bool
	}{
		{"valid", `{"email":"a@example.com"}`, "application/json; charset=utf-8", true},
		{"unknown", `{"password":"secret"}`, "application/json", false},
		{"trailing", `{} {}`, "application/json", false},
		{"media", `{}`, "text/plain", false},
		{"large", `{"email":"` + strings.Repeat("x", 1<<20) + `"}`, "application/json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			var dst struct {
				Email string `json:"email"`
			}
			err := DecodeJSON(httptest.NewRecorder(), req, &dst)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected decode result: %v", err)
			}
		})
	}
}

func TestIPDoesNotTrustForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Forwarded-For", "attacker")
	req.Header.Set("X-Real-IP", "attacker")
	if IP(req) != "192.0.2.1" {
		t.Fatal("trusted unconfigured proxy")
	}
}
