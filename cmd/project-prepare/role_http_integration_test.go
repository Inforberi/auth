package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/admission"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type roleHTTPSession struct{ actor operatordomain.Principal }

func (s roleHTTPSession) ValidateSession(context.Context, string) (*sessionservice.ValidationResult, error) {
	return nil, domain.ErrUnavailable
}

func (s roleHTTPSession) ValidateSessionWithoutRefresh(context.Context, string) (*sessionservice.ValidationResult, error) {
	return &sessionservice.ValidationResult{UserID: s.actor.UserID, TokenHash: s.actor.TokenHash}, nil
}

func roleHTTPDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal,
	base domain.RoleCreation, realm domain.ID, registry *projectruntime.Registry, permissions settings.Catalog,
) {
	t.Helper()
	ctx := t.Context()
	_, err := admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.projects.read')`, actor.UserID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `WITH restored_session AS (UPDATE auth.sessions SET revoked_at=NULL WHERE token_hash=$2),
		 cleared_read AS (DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read')
		 INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_access.manage') ON CONFLICT DO NOTHING`, actor.UserID, actor.TokenHash)
		require.NoError(t, err)
	})
	cfg := &config.Config{Platform: config.PlatformConfig{Enabled: true, RealmID: string(realm), Origin: "https://console.auth.example", ProjectAuthDomain: "auth.example", StorageTarget: "primary", Operations: admission.DefaultConfig(), Resources: config.DefaultPlatformResources(), Runtime: config.ProjectRuntimeConfig{
		Enabled: true, CatalogURL: "postgres://reader@/catalog?host=/var/run/postgresql&sslmode=disable", MasterKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), MasterKeyID: "fixture",
		StorageHost: "/var/run/postgresql", StoragePort: 5432, MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1, MaxAcquiring: 4, AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute, SyncInterval: time.Minute, SyncTimeout: time.Second,
	}}}
	cfg.Postgres.MaxConns = 4
	cfg.MFA.Enabled = true
	cfg.Browser.AllowedOrigins = []string{cfg.Platform.Origin}
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "fixture", "fixture"
	cfg.Password.ResetURL = cfg.Platform.Origin + "/reset"
	// The session adapter supplies a SQL proof fixture. Real SQL guards still
	// reject revoked proofs; login/session transport is covered by its own suite.
	handler, err := router.NewOperator(router.Handlers{
		Config: cfg, Logger: zap.NewNop(), Projects: projecthttp.New(projectservice.New(managed, nil), zap.NewNop()),
		ProjectRoles:    projecthttp.NewRoles(projectservice.NewRoles(catalog.NewRuntimeRoles(managed, registry, permissions)), zap.NewNop()),
		ProjectCapacity: func(next http.Handler) http.Handler { return next }, PasswordHandler: &passwordhttp.PasswordHandler{}, MFA: &mfahttp.Handler{}, Session: &sessionhttp.Handler{}, Middleware: sessionhttp.New(roleHTTPSession{actor}, zap.NewNop()), Recovery: &passwordhttp.RecoveryHandler{}, ReadyCheck: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	call := func(method, path string, payload any, status int) []byte {
		t.Helper()
		var body []byte
		if payload != nil {
			body, err = json.Marshal(payload)
			require.NoError(t, err)
		}
		request, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		require.NoError(t, err)
		request.Host = "console.auth.example"
		request.Header.Set("Origin", cfg.Platform.Origin)
		request.Header.Set("Content-Type", "application/json")
		request.AddCookie(&http.Cookie{Name: sessionhttp.SessionCookieName, Value: strings.Repeat("A", 43)})
		response, err := client.Do(request)
		require.NoError(t, err)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		require.NoError(t, response.Body.Close())
		require.NoError(t, readErr)
		require.Equal(t, status, response.StatusCode, "%s %s: %s", method, path, data)
		require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		require.Empty(t, response.Header.Values("Set-Cookie"))
		return data
	}
	input := projecthttp.CreatePlatformRoleRequest{OperationID: "f4000000-0000-4000-8000-000000000001", ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration, Key: "bridge_http_editor", Name: "HTTP editor", Reason: "HTTP fixture", Permissions: []accessdomain.PermissionKey{settings.UsersRead}}
	createPath := "/api/v1/platform/projects/" + string(base.ProjectID) + "/roles"
	operationPath := "/api/v1/platform/projects/" + string(base.ProjectID) + "/role-operations/" + string(input.OperationID)
	var first, replay projecthttp.CreatePlatformRoleResponse
	require.NoError(t, json.Unmarshal(call("POST", createPath, input, 201), &first))
	require.NotNil(t, first.Role)
	require.NotEmpty(t, first.Role.ID)
	require.True(t, first.CatalogRecorded)
	require.Equal(t, input.Permissions, first.Role.Permissions)
	require.NoError(t, json.Unmarshal(call("POST", createPath, input, 200), &replay))
	require.True(t, replay.Replayed)
	require.Equal(t, first.Role.ID, replay.Role.ID)
	changed := input
	changed.Name = "Changed payload"
	call("POST", createPath, changed, 409)
	call("GET", operationPath, nil, 200)
	otherPath := "/api/v1/platform/projects/a2000000-0000-4000-8000-000000000099/role-operations/" + string(input.OperationID)
	call("GET", otherPath, nil, 404)
	call("POST", otherPath+"/reconcile", nil, 404)
	var before, after int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, input.OperationID).Scan(&before))
	_, err = admin.Exec(ctx, `DELETE FROM platform.project_role_outcomes WHERE operation_id=$1`, input.OperationID)
	require.NoError(t, err)
	var outcome projecthttp.RoleOutcomeResponse
	require.NoError(t, json.Unmarshal(call("GET", operationPath, nil, 200), &outcome))
	require.False(t, outcome.Committed)
	require.Nil(t, outcome.Role)
	require.NoError(t, json.Unmarshal(call("POST", operationPath+"/reconcile", nil, 200), &outcome))
	require.True(t, outcome.Committed)
	require.Equal(t, first.Role.ID, outcome.Role.ID)
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM platform.project_role_admissions WHERE operation_id=$1`, input.OperationID).Scan(&after))
	require.Equal(t, before, after)
	unsupported := input
	unsupported.OperationID = "f4000000-0000-4000-8000-000000000002"
	unsupported.Key = "bridge_http_mfa"
	unsupported.MFARequired = true
	data := call("POST", createPath, unsupported, 409)
	require.Contains(t, string(data), "mfa_not_ready")
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_access.manage'`, actor.UserID)
	require.NoError(t, err)
	call("POST", createPath, input, 403)
	call("GET", operationPath, nil, 200)
	call("POST", operationPath+"/reconcile", nil, 200)
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.projects.read'`, actor.UserID)
	require.NoError(t, err)
	call("GET", operationPath, nil, 403)
	call("POST", operationPath+"/reconcile", nil, 403)
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, actor.TokenHash)
	require.NoError(t, err)
	call("POST", createPath, input, 403)
}
