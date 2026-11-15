package admin_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

const operatorFixtureRole = "auth_platform_operator_test"

func operatorFixture(t *testing.T) (*pgxpool.Pool, authapp.Dependencies, *config.Config) {
	t.Helper()
	dsn, addr := os.Getenv("AUTH_OPERATOR_TEST_DATABASE_URL"), os.Getenv("AUTH_OPERATOR_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("requires dedicated auth_platform_test and sandbox Redis DB15")
	}
	pc, err := pgxpool.ParseConfig(dsn)
	host, _, addrErr := net.SplitHostPort(addr)
	if err != nil || pc.ConnConfig.Database != "auth_platform_test" || pc.ConnConfig.User != "auth" ||
		(pc.ConnConfig.Host != "/var/run/postgresql" && pc.ConnConfig.Host != "127.0.0.1") || addrErr != nil ||
		(host != "127.0.0.1" && (host != "auth-sandbox-redis-1" || pc.ConnConfig.Host != "/var/run/postgresql")) {
		t.Fatal("refusing non-dedicated operator fixture")
	}
	pc.MaxConns = 6
	ctx := t.Context()
	admin, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var clean bool
	if err := admin.QueryRow(ctx, `SELECT to_regnamespace('auth') IS NULL AND to_regnamespace('platform') IS NULL
		AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='auth_platform_operator_test')`).Scan(&clean); err != nil || !clean {
		t.Fatal("fixture SQL/role is not empty", err)
	}
	roleCreated := false
	t.Cleanup(func() {
		if roleCreated {
			if _, err := admin.Exec(context.Background(), `REVOKE CONNECT ON DATABASE auth_platform_test FROM auth_platform_operator_test; DROP ROLE auth_platform_operator_test`); err != nil {
				t.Error("fixture role cleanup", err)
			}
		}
	})
	root := os.Getenv("AUTH_OPERATOR_TEST_ROOT")
	if root == "" {
		root = filepath.Join("..", "..", "..", "..")
	}
	read := func(path string) string {
		source, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return string(source)
	}
	for _, migration := range []string{"auth/000001_init", "admin/000001_catalog", "admin/000002_operators", "admin/000003_project_names", "admin/000004_operator_management", "admin/000005_project_operations"} {
		if _, err := admin.Exec(ctx, "BEGIN;"+read("migrations/"+migration+".up.sql")+"COMMIT;"); err != nil {
			t.Fatal("fixture migration", err)
		}
		t.Cleanup(func() {
			if _, err := admin.Exec(context.Background(), "BEGIN;"+read("migrations/"+migration+".down.sql")+"COMMIT;"); err != nil {
				t.Error("fixture migration cleanup", err)
			}
		})
	}
	var realm string
	if err := admin.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm`).Scan(&realm); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE ROLE auth_platform_operator_test LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	roleCreated = true
	grants := strings.NewReplacer("auth_platform_runtime", operatorFixtureRole, "DATABASE auth_platform ", "DATABASE auth_platform_test ").Replace(read("deploy/postgres/grants/platform-runtime-grants.sql"))
	if _, err := admin.Exec(ctx, grants); err != nil {
		t.Fatal("runtime grants", err)
	}
	runtimeConfig := pc.Copy()
	runtimeConfig.ConnConfig.User = operatorFixtureRole
	runtime, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("AUTH_OPERATOR_TEST_REDIS_PASSWORD"), DB: 15, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = rdb.Close() })
	if count, err := rdb.DBSize(ctx).Result(); err != nil || count != 0 {
		t.Fatal("Redis fixture DB15 must be empty", err)
	}
	scope, err := realmscope.New("platform", realm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, purpose := range []string{
			"email-verification-limit",
			"password-limit",
			"mfa-limit",
			"platform-project-admission",
		} {
			prefix, err := scope.RedisPrefix(purpose, "unused")
			if err != nil {
				t.Error(err)
				continue
			}
			// DB15 was empty and is exclusive to this fixture, never a production keyspace.
			keys, err := rdb.Keys(cleanup, prefix+"*").Result()
			if err != nil || len(keys) > 256 {
				t.Error("unexpected fixture key count", err)
				continue
			}
			if len(keys) > 0 {
				if err := rdb.Del(cleanup, keys...).Err(); err != nil {
					t.Error(err)
				}
			}
		}
		if count, err := rdb.DBSize(cleanup).Result(); err != nil || count != 0 {
			t.Error("unexpected Redis fixture leftovers", count, err)
		}
	})
	owner, err := operatorpostgres.New(admin, operatordomain.RealmID(realm))
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.CheckRuntime(ctx, true); err == nil {
		t.Fatal("superuser was accepted as platform runtime")
	}
	return admin, authapp.Dependencies{
		Pool: runtime, Redis: rdb, Logger: zap.NewNop(), Scope: scope,
		Hash: hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1),
	}, appfixtures.OperatorConfig(realm)
}
