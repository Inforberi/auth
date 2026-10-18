package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

type operatorReadSession struct{ refresh, noRefresh int }

func (s *operatorReadSession) ValidateSession(context.Context, string) (*sessionservice.ValidationResult, error) {
	s.refresh++
	return nil, nil
}

func (s *operatorReadSession) ValidateSessionWithoutRefresh(context.Context, string) (*sessionservice.ValidationResult, error) {
	s.noRefresh++
	return &sessionservice.ValidationResult{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}, nil
}

type operatorReadCatalog struct{ calls int }

func (s *operatorReadCatalog) List(context.Context, operatordomain.Principal, projectservice.ListInput) (projectservice.ListResult, error) {
	s.calls++
	return projectservice.ListResult{}, nil
}

func (s *operatorReadCatalog) Read(context.Context, operatordomain.Principal, projectdomain.ID) (projectdomain.Project, error) {
	s.calls++
	return projectdomain.Project{}, nil
}

func TestOperatorCatalogRouteBoundary(t *testing.T) {
	cfg := &config.Config{Platform: config.PlatformConfig{Enabled: true, RealmID: "1c82c477-3a57-4823-8c49-a476550d8a21", Origin: "https://console.auth.example"}}
	cfg.MFA.Enabled = true
	cfg.Browser.AllowedOrigins = []string{cfg.Platform.Origin}
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "tls.crt", "tls.key"
	cfg.Password.ResetURL = cfg.Platform.Origin + "/reset"
	sessions, catalog := &operatorReadSession{}, &operatorReadCatalog{}
	h := Handlers{
		Config: cfg, Projects: projecthttp.New(catalog, nil), PasswordHandler: &passwordhttp.PasswordHandler{}, MFA: &mfahttp.Handler{},
		Session: &sessionhttp.Handler{}, Middleware: sessionhttp.New(sessions, nil), Recovery: &passwordhttp.RecoveryHandler{}, ReadyCheck: func(context.Context) error { return nil },
	}
	router, err := NewOperator(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method, host, origin, path string
		cookie                     bool
		status                     int
	}{
		{"GET", cfg.Platform.Origin, cfg.Platform.Origin, "/api/v1/platform/projects", true, 200},
		{"GET", cfg.Platform.Origin, "", "/api/v1/platform/projects", true, 200},
		{"GET", cfg.Platform.Origin, cfg.Platform.Origin, "/api/v1/platform/projects", false, 401},
		{"GET", cfg.Platform.Origin, "https://project.auth.example", "/api/v1/platform/projects", true, 403},
		{"GET", "https://project.auth.example", cfg.Platform.Origin, "/api/v1/platform/projects", true, 404},
		{"GET", "http://console.auth.example", cfg.Platform.Origin, "/api/v1/platform/projects", true, 404},
		{"OPTIONS", cfg.Platform.Origin, cfg.Platform.Origin, "/api/v1/platform/projects", true, 403},
		{"POST", cfg.Platform.Origin, cfg.Platform.Origin, "/api/v1/platform/projects", true, 405},
		{"POST", cfg.Platform.Origin, cfg.Platform.Origin, "/api/v1/platform/projects/id/suspend", true, 404},
	} {
		request := httptest.NewRequest(test.method, test.host+test.path, nil)
		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
		}
		if test.cookie {
			request.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)})
		}
		before := catalog.calls
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s: %d want %d", test.method, test.host, response.Code, test.status)
		}
		if test.status != 200 && catalog.calls != before {
			t.Fatal("rejected request reached catalog")
		}
		if len(response.Result().Cookies()) != 0 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("read changed cookies or cache policy")
		}
	}
	if sessions.refresh != 0 || sessions.noRefresh < 2 {
		t.Fatal("catalog refreshed sessions", sessions)
	}
	response := httptest.NewRecorder()
	New(h).ServeHTTP(response, httptest.NewRequest("GET", cfg.Platform.Origin+"/api/v1/platform/projects", nil))
	if response.Code != 404 {
		t.Fatal("standalone published platform API", response.Code)
	}
}
