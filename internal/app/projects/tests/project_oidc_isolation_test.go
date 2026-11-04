package projects_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/app/projects/browser"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type oidcIsolationFixture struct {
	projects           projectIsolationHTTP
	provider           *controlledOIDCProvider
	webs               [2]isolationHTTP
	clientIDs, secrets [2]map[string]string
	ciphers            [2]map[string]*secretbox.Cipher
	emptySecrets       [2]map[string][]byte
	prefixes           [2]map[string]string
	modes              [2]string
}

func TestTwoProjectOIDCIsolationSQL(t *testing.T) {
	if os.Getenv("AUTH_PREPARE_TEST_CATALOG_URL") == "" {
		t.Skip("requires explicit disposable PG/Redis and isolated provider hosts")
	}
	// Install the fixture trust before any connection can initialise the system root cache.
	provider := newControlledOIDCProvider(t)
	pair := prepareHTTPProjects(t)
	projects := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	require.NotEqual(t, pair.a.Binding.DatabaseOID, pair.b.Binding.DatabaseOID)
	f := prepareOIDCIsolation(t, projects, provider)
	for _, name := range []string{"google", "telegram"} {
		logins := checkOIDCProjectCallbacks(t, t.Context(), f, name)
		checkOIDCProviderRevisions(t, t.Context(), f, name, logins)
	}
	for _, db := range projects.databases {
		var users int
		require.NoError(t, db.QueryRow(t.Context(), `SELECT count(DISTINCT user_id) FROM auth.linked_identities WHERE subject=$1`, "isolated-oidc-subject").Scan(&users))
		require.Equal(t, 2, users, "matching subjects from different issuers must not merge accounts")
	}
}

func prepareOIDCIsolation(t *testing.T, projects projectIsolationHTTP, provider *controlledOIDCProvider) oidcIsolationFixture {
	t.Helper()
	ctx := t.Context()
	f := oidcIsolationFixture{projects: projects, provider: provider}
	var configs [2][2]projectmethods.ProjectOIDCConfig
	for i, key := range projects.projects {
		f.clientIDs[i], f.secrets[i] = map[string]string{}, map[string]string{}
		f.ciphers[i], f.prefixes[i] = map[string]*secretbox.Cipher{}, map[string]string{}
		f.emptySecrets[i] = map[string][]byte{}
		db := projects.databases[i]
		require.NoError(t, db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings`).Scan(&f.modes[i]))
		_, err := db.Exec(ctx, `CREATE TEMP TABLE isolation_providers_before AS TABLE auth.provider_settings;
 UPDATE auth.auth_settings SET version=version+1,google_enabled=true,telegram_enabled=true,
 registration_enabled=true,google_registration_enabled=true,telegram_registration_enabled=true;
 UPDATE auth.mfa_settings SET mode='optional'`)
		require.NoError(t, err)
		configuration, err := projects.deps.Reader.LoadAuthConfiguration(ctx, key, projects.deps.Registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		for j, name := range []string{"google", "telegram"} {
			id := fmt.Sprintf("isolation-%d.apps.googleusercontent.com", i)
			if name == "telegram" {
				id = fmt.Sprintf("10000000%d", i+1)
			}
			f.clientIDs[i][name], f.secrets[i][name] = id, fmt.Sprintf("fixture-%s-project-%d", name, i)
			purpose, err := scope.Purpose("provider-" + name + ":v1")
			require.NoError(t, err)
			cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
			require.NoError(t, err)
			f.emptySecrets[i][name], err = cipher.Seal(nil)
			require.NoError(t, err)
			sealed, err := cipher.Seal([]byte(f.secrets[i][name]))
			require.NoError(t, err)
			_, err = db.Exec(ctx, `INSERT INTO auth.provider_settings(provider,version,client_id,secret,secret_set) VALUES($1,1,$2,$3,true)
 ON CONFLICT(provider) DO UPDATE SET version=auth.provider_settings.version+1,client_id=EXCLUDED.client_id,secret=EXCLUDED.secret,secret_set=true`, name, id, sealed)
			require.NoError(t, err)
			purpose, err = scope.Purpose(name + "-login:v1")
			require.NoError(t, err)
			f.ciphers[i][name], err = secretbox.NewScoped(configuration.EncryptionKey(), purpose)
			require.NoError(t, err)
			prefix, err := scope.RedisPrefix("oidc-"+name, "auth:"+name)
			require.NoError(t, err)
			f.prefixes[i][name] = strings.TrimSuffix(prefix, ":")
			for _, suffix := range []string{":limit:" + f.ciphers[i][name].Digest("127.0.0.1"), ":limit:global"} {
				projects.redisKeys[f.prefixes[i][name]+suffix] = struct{}{}
			}
			configs[i][j] = projectmethods.ProjectOIDCConfig{Provider: name, Enabled: true, RedirectURI: projects.origins[i] + "/api/v1/auth/" + name + "/callback", IPLimit: 100, GlobalLimit: 1000, MFA: projects.password.MFA, Session: projects.password.Session, Timeout: 5 * time.Second}
		}
	}
	f.registerCleanup(t, ctx)
	owners := projectmethods.NewProjectOIDCClients(ctx)
	t.Cleanup(owners.Close)
	projects.deps.OIDCClients = owners
	handler, err := projectbrowser.NewProjectHTTP(projectprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test",
		Residents:      projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &projects.password.Session,
	}, projects.deps, func(_ context.Context, key projectruntime.Key, origin string) (projectprofile.ProjectProfileConfig, error) {
		for i, expected := range projects.projects {
			if key == expected && origin == projects.origins[i] {
				return projectprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &projects.password, Google: &configs[i][0], Telegram: &configs[i][1], Timeout: 5 * time.Second}, nil
			}
		}
		return projectprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
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

func (f oidcIsolationFixture) registerCleanup(t *testing.T, ctx context.Context) {
	t.Helper()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		for i, db := range f.projects.databases {
			var users []string
			rows, err := db.Query(cleanup, `SELECT user_id::text FROM auth.linked_identities WHERE subject=$1 AND issuer IN('https://accounts.google.com','https://oauth.telegram.org')`, "isolated-oidc-subject")
			require.NoError(t, err)
			for rows.Next() {
				var user string
				require.NoError(t, rows.Scan(&user))
				users = append(users, user)
			}
			require.NoError(t, rows.Err())
			rows.Close()
			for _, table := range []string{"identity_audit", "mfa_audit", "password_audit"} {
				_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE user_id=ANY($1::uuid[])`, users)
				require.NoError(t, err)
			}
			_, err = db.Exec(cleanup, `DELETE FROM auth.users WHERE id=ANY($1::uuid[])`, users)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.provider_settings; INSERT INTO auth.provider_settings SELECT * FROM isolation_providers_before`)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=$1`, f.modes[i])
			require.NoError(t, err)
		}
	})
}
