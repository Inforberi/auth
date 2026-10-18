package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestOperatorHTTPAllowlist(t *testing.T) {
	cfg := &config.Config{Platform: config.PlatformConfig{Enabled: true, RealmID: "1c82c477-3a57-4823-8c49-a476550d8a21", Origin: "https://console.auth.example"}}
	cfg.MFA.Enabled = true
	cfg.Browser.AllowedOrigins = []string{cfg.Platform.Origin}
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "tls.crt", "tls.key"
	cfg.Password.ResetURL = cfg.Platform.Origin + "/reset"
	handler, err := NewOperator(Handlers{
		Config: cfg, PasswordHandler: &passwordhttp.PasswordHandler{}, MFA: &mfahttp.Handler{},
		Session: &sessionhttp.Handler{}, Middleware: &sessionhttp.Middleware{}, Recovery: &passwordhttp.RecoveryHandler{},
		ReadyCheck: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/api/v1/auth/register/email", "/api/v1/auth/login/email", "/api/v1/auth/google/start", "/api/v1/auth/telegram/start",
		"/api/v1/auth/email-otp/request", "/api/v1/auth/token", "/api/v1/admin/users", "/api/v1/admin/roles", "/swagger/index.html",
		"/api/v1/auth/mfa/totp", "/api/v1/auth/mfa/totp/enrollment", "/api/v1/auth/mfa/recovery/start",
	} {
		r := httptest.NewRequest(http.MethodPost, cfg.Platform.Origin+path, nil)
		r.Header.Set("Origin", cfg.Platform.Origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("unexpected exposed path %s: %d", path, w.Code)
		}
	}
	for _, test := range []struct {
		host, scheme, forwarded string
		status                  int
	}{
		{"console.auth.example", "https", "", 200},
		{"project.auth.example", "https", "console.auth.example", 404},
		{"console.auth.example", "http", "", 404},
	} {
		r := httptest.NewRequest(http.MethodGet, test.scheme+"://"+test.host+"/health/live", nil)
		r.Header.Set("X-Forwarded-Host", test.forwarded)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatal("authority boundary", test, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, cfg.Platform.Origin+"/api/v1/admin/auth/login/email", nil)
	r.Header.Set("Origin", "https://project.auth.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("foreign Origin reached handler", w.Code)
	}
	if cfg.Browser.CORSEnabled {
		t.Fatal("platform unexpectedly enabled CORS")
	}
}
