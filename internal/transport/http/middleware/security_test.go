package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSecurityHeaders(t *testing.T) {
	for _, path := range []string{"/auth", "/swagger/index.html", "/swagger-evil"} {
		w := httptest.NewRecorder()
		SecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal(w.Header())
		}
		strict := strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'")
		if strict == strings.HasPrefix(path, "/swagger/") {
			t.Fatal("Swagger/API CSP scope incorrect")
		}
	}
}

func TestRecovererDoesNotLogSecrets(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	w := httptest.NewRecorder()
	Recoverer(zap.New(core))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("password-token-secret") })).ServeHTTP(w, httptest.NewRequest("POST", "/auth?token=secret", nil))
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret") || logs.Len() != 1 {
		t.Fatal(w.Code, w.Body.String(), logs.Len())
	}
	if strings.Contains(logs.All()[0].Message, "secret") || len(logs.All()[0].Context) != 0 {
		t.Fatal("panic secret leaked")
	}
}

func TestRecovererPreservesAbortWithoutWrapper(t *testing.T) {
	defer func() {
		if value := recover(); value != http.ErrAbortHandler {
			t.Fatal("abort changed", value)
		}
	}()
	Recoverer(zap.NewNop())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(fmt.Errorf("private wrapper: %w", http.ErrAbortHandler))
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}
