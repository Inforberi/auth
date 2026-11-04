package projects_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

const isolationTokenClient = "isolated-reports"

type tokenIsolationFixture struct {
	projects projectIsolationHTTP
	configs  [2]projectnative.ProjectTokenConfig
	secrets  [2]string
	webs     [2]isolationHTTP
}

func TestTwoProjectTokenIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	projects := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	f := prepareTokenIsolation(t, projects)
	browser := checkProjectTokenIsolation(t, t.Context(), f)
	checkProjectNativeIsolation(t, t.Context(), f, browser)
}

func prepareTokenIsolation(t *testing.T, projects projectIsolationHTTP) tokenIsolationFixture {
	t.Helper()
	ctx := t.Context()
	issuance, err := projectnative.NewProjectTokenRedis(projects.deps.Redis)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, issuance.Close()) })
	projects.deps.IssuanceRedis = issuance
	f := tokenIsolationFixture{projects: projects}
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}})
	require.NoError(t, err)
	var names [2]string
	for i, db := range projects.databases {
		require.NoError(t, db.QueryRow(ctx, `SELECT current_database()`).Scan(&names[i]))
		_, err := db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,token_session_exchange_enabled=true,token_native_enabled=true;
 UPDATE auth.mfa_settings SET mode='optional';
 INSERT INTO auth.roles(key,name) VALUES('http_token_isolation','Token reader');
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'reports.read' FROM auth.roles WHERE key='http_token_isolation'`)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='http_token_isolation'`, httpIsolationUser)
		require.NoError(t, err)
		secret := make([]byte, 32)
		secret[0] = byte(i + 1)
		f.secrets[i] = base64.RawURLEncoding.EncodeToString(secret)
		digest := sha256.Sum256([]byte(f.secrets[i]))
		f.configs[i] = projectnative.ProjectTokenConfig{
			Enabled: true, Issuer: projects.origins[i], Catalog: catalog, Limits: tokenredis.DefaultLimits(), Timeout: 5 * time.Second,
			Introspection: &projectnative.ProjectIntrospectionConfig{Clients: []tokenservice.IntrospectionClientConfig{{ID: isolationTokenClient, SecretHashes: []string{hex.EncodeToString(digest[:])}, Audiences: []string{"reports"}}}, ConsumerPerMinute: 100, ProjectPerMinute: 200},
			Tokens:        tokenservice.Config{AccessTTL: time.Minute, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}, {Audience: "reports-export", Permissions: []accessdomain.PermissionKey{"reports.read"}}}, Native: &tokenservice.NativePolicy{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour, Sessions: projects.password.Session}},
			Native:        projectnative.ProjectNativeConfig{PasswordEnabled: true, Capacity: projects.password.Capacity, MFA: projects.password.MFA},
		}
	}
	require.NotEqual(t, names[0], names[1], "each project must use its own physical database")
	require.NotEqual(t, projects.projects[0].Binding.DatabaseOID, projects.projects[1].Binding.DatabaseOID)
	f.registerCleanup(t, ctx)
	handler, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute},
		Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &projects.password.Session,
	}, projects.deps, func(_ context.Context, key projectruntime.Key, origin string) (runtimeprofile.ProjectProfileConfig, error) {
		for i, expected := range projects.projects {
			if key == expected && origin == projects.origins[i] {
				return runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &projects.password, Tokens: &f.configs[i], Timeout: 5 * time.Second}, nil
			}
		}
		return runtimeprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
	}, nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	for i := range f.webs {
		f.webs[i] = isolationHTTP{server: server, origin: projects.origins[i]}
	}
	return f
}
