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

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/config"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/admission"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

type operatorRoles struct{ calls int }

type operatorUsers struct{ calls int }

func (s *operatorUsers) ListProjectUsers(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountservice.UserListInput) (accountservice.UserPage, error) {
	s.calls++
	return accountservice.UserPage{}, nil
}

func (s *operatorUsers) ReadProjectUser(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID) (accountservice.UserDetail, error) {
	s.calls++
	return accountservice.UserDetail{}, nil
}

func (s *operatorRoles) ListProjectRoles(context.Context, operatordomain.Principal, projectservice.ProjectRoleQuery) (projectservice.ProjectRolePage, error) {
	s.calls++
	return projectservice.ProjectRolePage{}, nil
}

func (s *operatorRoles) ReadProjectRole(context.Context, operatordomain.Principal, domain.DirectoryTarget, accessdomain.RoleID) (accessdomain.Role, error) {
	s.calls++
	return accessdomain.Role{}, nil
}

func (s *operatorRoles) ChangeRoleAssignment(context.Context, operatordomain.Principal, domain.RoleAssignment) (domain.RoleAssignmentResult, error) {
	s.calls++
	return domain.RoleAssignmentResult{}, nil
}

func (s *operatorRoles) CreateRole(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error) {
	s.calls++
	return domain.RoleCreationResult{}, nil
}

func (s *operatorRoles) ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error) {
	s.calls++
	return domain.RoleOutcome{}, nil
}

func (s *operatorRoles) ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleOutcome, error) {
	s.calls++
	return domain.RoleOutcome{}, nil
}

type operatorPolicy struct{ calls int }

func (s *operatorPolicy) ReadAuthPolicy(context.Context, operatordomain.Principal, domain.DirectoryTarget) (settingsdomain.Snapshot, error) {
	s.calls++
	return settingsdomain.Snapshot{}, nil
}

func (s *operatorPolicy) UpdateAuthPolicy(context.Context, operatordomain.Principal, domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error) {
	s.calls++
	return domain.AuthPolicyResult{}, nil
}

func (s *operatorPolicy) ReadAuthPolicyOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.AuthPolicyOutcome, error) {
	s.calls++
	return domain.AuthPolicyOutcome{}, nil
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
	users := &operatorUsers{}
	policy := &operatorPolicy{}
	h := Handlers{
		Config: cfg, Projects: projecthttp.New(&operatorReadCatalog{}, nil), ProjectRoles: projecthttp.NewRoles(roles, nil), ProjectUsers: projecthttp.NewUsers(users, nil), ProjectAuthPolicy: projecthttp.NewAuthPolicy(policy, settingsdomain.PublicMethods{}, nil), PasswordHandler: &passwordhttp.PasswordHandler{}, MFA: &mfahttp.Handler{}, Session: &sessionhttp.Handler{}, Middleware: sessionhttp.New(&operatorReadSession{}, nil), Recovery: &passwordhttp.RecoveryHandler{}, ReadyCheck: func(context.Context) error { return nil },
		ProjectCapacity: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capacityCalls++
				require.Equal(t, "project", chi.URLParam(r, "id"))
				next.ServeHTTP(w, r)
			})
		},
	}
	for _, path := range []string{
		"/projects/project/auth/settings", "/projects/project/auth/settings?expectedVersion=1&expectedGeneration=1", "/projects/project/auth/settings/operations/op",
		"/projects/project/roles", "/projects/project/role-operations/op", "/projects/project/role-operations/op/reconcile",
		"/projects/project/users/user/roles/role/grant", "/projects/project/users/user/roles/role/revoke",
		"/projects/project/roles?expectedVersion=1&expectedGeneration=1",
		"/projects/project/roles/role?expectedVersion=1&expectedGeneration=1",
		"/projects/project/users?expectedVersion=1&expectedGeneration=1",
		"/projects/project/users/user?expectedVersion=1&expectedGeneration=1",
	} {
		for _, tc := range []struct {
			origin string
			cookie bool
			status int
		}{
			{cfg.Platform.Origin, true, 200}, {"https://foreign.example", true, 403}, {cfg.Platform.Origin, false, 401},
		} {
			method, body, status := "POST", "", tc.status
			if strings.HasSuffix(path, "/grant") || strings.HasSuffix(path, "/revoke") {
				body = "{}"
			}
			if strings.HasSuffix(path, "/roles") {
				body = "{}"
				if status == 200 {
					status = 201
				}
			}
			if path == "/projects/project/auth/settings" {
				body = `{"policy":{"methods":{"password":false,"emailOtp":false,"google":false,"telegram":false},"registration":{"enabled":false,"google":false,"telegram":false},"passwordEmailVerification":"disabled","tokenIssuance":{"sessionExchange":false,"native":false}}}`
			}
			if strings.HasSuffix(path, "/op") {
				method = "GET"
			}
			if strings.Contains(path, "?") {
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
			before := roles.calls + users.calls + policy.calls
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, status, w.Code)
			if status >= 400 {
				require.Equal(t, before, roles.calls+users.calls+policy.calls)
			}
		}
	}
	require.Equal(t, 12, capacityCalls)
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
	unsafe.ProjectUsers = nil
	unsafe.ProjectAuthPolicy = nil
	disabled, err := NewOperator(unsafe)
	require.NoError(t, err)
	request := httptest.NewRequest("POST", cfg.Platform.Origin+"/api/v1/platform/projects/project/roles", strings.NewReader("{}"))
	request.Header.Set("Origin", cfg.Platform.Origin)
	request.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()
	disabled.ServeHTTP(response, request)
	require.Equal(t, 404, response.Code)
}
