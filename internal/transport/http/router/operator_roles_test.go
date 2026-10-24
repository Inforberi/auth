package router

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/admission"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

type operatorRoles struct{ calls int }

func (s *operatorRoles) CreateRole(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error) {
	s.calls++
	return domain.RoleCreationResult{}, nil
}

func (s *operatorRoles) ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error) {
	s.calls++
	return domain.RoleCreationOutcome{}, nil
}

func (s *operatorRoles) ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error) {
	s.calls++
	return domain.RoleCreationOutcome{}, nil
}

func roleRouteRuntime() config.ProjectRuntimeConfig {
	return config.ProjectRuntimeConfig{
		Enabled: true, CatalogURL: "postgres://reader@/catalog?host=/var/run/postgresql&sslmode=disable",
		MasterKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), MasterKeyID: "fixture",
		StorageHost: "/var/run/postgresql", StoragePort: 5432, MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1,
		MaxAcquiring: 4, AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute,
		SyncInterval: time.Minute, SyncTimeout: time.Second,
	}
}

func TestOperatorRoleRouteBoundary(t *testing.T) {
	cfg := &config.Config{Platform: config.PlatformConfig{Enabled: true, RealmID: "1c82c477-3a57-4823-8c49-a476550d8a21", Origin: "https://console.auth.example", ProjectAuthDomain: "auth.example", StorageTarget: "primary", Operations: admission.DefaultConfig(), Resources: config.DefaultPlatformResources(), Runtime: roleRouteRuntime()}}
	cfg.Postgres.MaxConns = 6
	cfg.MFA.Enabled = true
	cfg.Browser.AllowedOrigins = []string{cfg.Platform.Origin}
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "fixture", "fixture"
	cfg.Password.ResetURL = cfg.Platform.Origin + "/reset"
	roles := &operatorRoles{}
	capacityCalls := 0
	h := Handlers{
		Config: cfg, Projects: projecthttp.New(&operatorReadCatalog{}, nil), ProjectRoles: projecthttp.NewRoles(roles, nil), PasswordHandler: &passwordhttp.PasswordHandler{}, MFA: &mfahttp.Handler{}, Session: &sessionhttp.Handler{}, Middleware: sessionhttp.New(&operatorReadSession{}, nil), Recovery: &passwordhttp.RecoveryHandler{}, ReadyCheck: func(context.Context) error { return nil },
		ProjectCapacity: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capacityCalls++
				require.Equal(t, "project", chi.URLParam(r, "id"))
				next.ServeHTTP(w, r)
			})
		},
	}
	for _, path := range []string{"/projects/project/roles", "/projects/project/role-operations/op", "/projects/project/role-operations/op/reconcile"} {
		for _, tc := range []struct {
			origin string
			cookie bool
			status int
		}{
			{cfg.Platform.Origin, true, 200}, {"https://foreign.example", true, 403}, {cfg.Platform.Origin, false, 401},
		} {
			method, body, status := "POST", "", tc.status
			if strings.HasSuffix(path, "/roles") {
				body = "{}"
				if status == 200 {
					status = 201
				}
			}
			if strings.HasSuffix(path, "/op") {
				method = "GET"
			}
			router, err := NewOperator(h)
			require.NoError(t, err)
			r := httptest.NewRequest(method, cfg.Platform.Origin+"/api/v1/platform"+path, strings.NewReader(body))
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", "application/json")
			if tc.cookie {
				r.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)})
			}
			before := roles.calls
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, status, w.Code)
			if status >= 400 {
				require.Equal(t, before, roles.calls)
			}
		}
	}
	require.Equal(t, 3, capacityCalls)
	unsafe := h
	unsafe.ProjectCapacity = nil
	_, err := NewOperator(unsafe)
	require.Error(t, err)
	unsafe = h
	copyCfg := *cfg
	copyCfg.Platform.Runtime.Enabled = false
	unsafe.Config = &copyCfg
	_, err = NewOperator(unsafe)
	require.Error(t, err)
	unsafe.ProjectRoles = nil
	disabled, err := NewOperator(unsafe)
	require.NoError(t, err)
	request := httptest.NewRequest("POST", cfg.Platform.Origin+"/api/v1/platform/projects/project/roles", strings.NewReader("{}"))
	request.Header.Set("Origin", cfg.Platform.Origin)
	request.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()
	disabled.ServeHTTP(response, request)
	require.Equal(t, 404, response.Code)
}
