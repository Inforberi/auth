package projects_test

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	profilefactory "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

func projectHTTPIsolationDrill(t *testing.T, admin *pgx.Conn, reader *runtimepostgres.RuntimeCredentialReader, a, b projectruntime.Key, target projectruntime.Target) {
	t.Helper()
	f := newProjectIsolationHTTP(t, admin, reader, a, b, target)
	webs, handler, builds := f.serve(t, runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, Timeout: 5 * time.Second})
	checkProjectHTTPIsolation(t, t.Context(), admin, f.databases, a, webs, handler)
	for i := range builds {
		require.EqualValues(t, 1, builds[i].Load(), "both resident profiles stay warm; suspended A must not be rebuilt")
	}
}

type projectIsolationHTTP struct {
	admin          *pgx.Conn
	databases      [2]*pgx.Conn
	origins        [2]string
	projects       [2]projectruntime.Key
	traces         [2]func(string, string, any)
	passwordCipher [2]*secretbox.Cipher
	passwordPrefix [2]string
	redisKeys      map[string]struct{}
	password       projectmethods.ProjectPasswordConfig
	deps           runtimeprofile.ProjectProfileDependencies
}

func newProjectIsolationHTTP(t *testing.T, admin *pgx.Conn, reader *runtimepostgres.RuntimeCredentialReader, a, b projectruntime.Key, target projectruntime.Target) projectIsolationHTTP {
	t.Helper()
	ctx := t.Context()
	registry, err := projectruntime.New(projectruntime.Config{
		MaxRuntimes: 2, ConnectionsPerProject: 1, ConnectionBudget: 2, MaxAcquiring: 4,
		AcquireTimeout: 3 * time.Second, OpenTimeout: 3 * time.Second, IdleTimeout: time.Minute,
	}, map[string]projectruntime.Target{a.Binding.StorageTarget: target}, reader, schemapostgres.CheckRuntimeConnection)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, registry.Close(cleanup))
	})
	addr := os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_ADDR")
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_PROJECT_PASSWORD_TEST_REDIS_PASSWORD"), DB: 15})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	count, err := rdb.DBSize(ctx).Result()
	require.NoError(t, err)
	require.Zero(t, count, "two-project HTTP test requires exclusive RedisDB15")
	keys := map[string]struct{}{}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		known := make([]string, 0, len(keys))
		for key := range keys {
			known = append(known, key)
		}
		if len(known) != 0 {
			require.NoError(t, rdb.Del(cleanup, known...).Err())
		}
		count, err := rdb.DBSize(cleanup).Result()
		require.NoError(t, err)
		require.Zero(t, count)
	})
	hash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1)
	encoded, err := hash.GenerateHash(ctx, []byte(httpIsolationPassword))
	require.NoError(t, err)
	var origins [2]string
	var databases [2]*pgx.Conn
	var traces [2]func(string, string, any)
	var passwordCiphers [2]*secretbox.Cipher
	var passwordPrefixes [2]string
	for i, key := range []projectruntime.Key{a, b} {
		require.NoError(t, admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, key.Binding.ProjectID).Scan(&origins[i]))
		cfg := admin.Config().Copy()
		cfg.Database = "authp_" + strings.ReplaceAll(string(key.Binding.ProjectID), "-", "")
		db, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close(context.WithoutCancel(ctx))) })
		databases[i] = db
		seedHTTPIsolationUser(t, ctx, db, encoded)
		configuration, err := reader.LoadAuthConfiguration(ctx, key, registry)
		require.NoError(t, err)
		scope, err := realmscope.New("project", string(key.Binding.ProjectID))
		require.NoError(t, err)
		purpose, err := scope.Purpose("password-reset:v1")
		require.NoError(t, err)
		passwordCipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		prefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
		require.NoError(t, err)
		passwordCiphers[i], passwordPrefixes[i] = passwordCipher, prefix
		for _, name := range []string{"login-ip:127.0.0.1", "login-email:" + httpIsolationEmail, "login-global"} {
			keys[prefix+passwordCipher.Digest(name)] = struct{}{}
		}
		purpose, err = scope.Purpose("mfa:v1")
		require.NoError(t, err)
		cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
		require.NoError(t, err)
		prefix, err = scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
		require.NoError(t, err)
		for _, name := range []string{cipher.Digest("user:" + httpIsolationUser), cipher.Digest("login:factor-user:" + httpIsolationUser), "login:ip:" + cipher.Digest("127.0.0.1"), "project"} {
			keys[prefix+name] = struct{}{}
		}
		traces[i] = httpIsolationTrace(prefix, cipher, keys)
	}
	password := projectPasswordFixtureConfig()
	password.MFA = mfaservice.Config{Enabled: true, Issuer: "HTTP isolation", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	return projectIsolationHTTP{
		admin:     admin,
		databases: databases, origins: origins, projects: [2]projectruntime.Key{a, b}, traces: traces,
		passwordCipher: passwordCiphers, passwordPrefix: passwordPrefixes, redisKeys: keys, password: password,
		deps: runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: registry, Reader: reader, Redis: rdb, Hash: hash}},
	}
}

func (f projectIsolationHTTP) serve(t *testing.T, features runtimeprofile.ProjectProfileConfig) ([2]isolationHTTP, *projectbrowser.ProjectHTTP, *[2]atomic.Int32) {
	t.Helper()
	ctx := t.Context()
	builds := new([2]atomic.Int32)
	handler, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test",
		Residents:      projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute},
		Capacity:       middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &f.password.Session,
	}, f.deps.Reader, profilefactory.NewFactory(f.deps,
		func(_ context.Context, key projectruntime.Key, origin string) (runtimeprofile.ProjectProfileConfig, error) {
			for i, expected := range f.projects {
				if key == expected && origin == f.origins[i] {
					builds[i].Add(1)
					return features, nil
				}
			}
			return runtimeprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
		}), nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	server.Client().Timeout = 10 * time.Second
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	webs := [2]isolationHTTP{{server: server, origin: f.origins[0], trace: f.traces[0]}, {server: server, origin: f.origins[1], trace: f.traces[1]}}
	return webs, handler, builds
}

func (f projectIsolationHTTP) trackLogin(email string) {
	for i := range f.projects {
		f.redisKeys[f.passwordPrefix[i]+f.passwordCipher[i].Digest("login-email:"+email)] = struct{}{}
	}
}
