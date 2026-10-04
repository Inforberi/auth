package core_middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRequestLoggerRedactsURL(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	r := chi.NewRouter()
	r.Use(RequestLogger(zap.New(core)))
	r.Get("/reset/{token}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	req := httptest.NewRequest("GET", "/reset/topsecret?token=querysecret", nil)
	req.Header.Set("Authorization", "Bearer headersecret")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request ID")
	}
	entry := logs.All()[0]
	if entry.ContextMap()["route"] != "/reset/{token}" {
		t.Fatal("route pattern missing")
	}
	for _, field := range entry.Context {
		if strings.Contains(field.String, "secret") {
			t.Fatal("secret in access log")
		}
	}
}
