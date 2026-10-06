package router

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/app/config"
)

func TestHealthAndSwaggerPolicy(t *testing.T) {
	for _, tc := range []struct {
		path   string
		check  func(context.Context) error
		status int
	}{
		{"/health/live", nil, 200},
		{"/health/ready", func(ctx context.Context) error { return nil }, 200},
		{"/health/ready", func(ctx context.Context) error { return errors.New("secret DSN") }, 503},
		{"/swagger/index.html", nil, 404},
	} {
		h := New(Handlers{Config: &config.Config{}, ReadyCheck: tc.check})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", tc.path, nil))
		if rr.Code != tc.status {
			t.Fatalf("%s status %d", tc.path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "secret DSN") {
			t.Fatal("health response leaked dependency error")
		}
	}
	cfg := &config.Config{Swagger: config.SwaggerConfig{Enabled: true, Username: "user", Password: "secret"}}
	rr := httptest.NewRecorder()
	New(Handlers{Config: cfg}).ServeHTTP(rr, httptest.NewRequest("GET", "/swagger/index.html", nil))
	if rr.Code != 401 {
		t.Fatalf("Swagger unprotected: %d", rr.Code)
	}
}

func TestReadinessDeadline(t *testing.T) {
	h := New(Handlers{ReadyCheck: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }})
	rr := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/health/ready", nil))
	if rr.Code != 503 || time.Since(start) > 3*time.Second {
		t.Fatal("readiness did not respect its deadline")
	}
}
