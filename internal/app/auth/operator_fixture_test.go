package auth

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

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

const operatorFixtureRole = "auth_platform_operator_test"

func operatorConfig(realm string) *config.Config {
	cfg := &config.Config{
		Platform:     config.PlatformConfig{Enabled: true, RealmID: realm, Origin: "https://console.auth.example"},
		HTTP:         requestmiddleware.CapacityConfig{MaxInFlight: 16, RequestTimeout: 10 * time.Second},
		Browser:      requestmiddleware.OriginConfig{AllowedOrigins: []string{"https://console.auth.example"}},
		Account:      accountservice.Config{URL: "https://console.auth.example/verify", EncryptionKey: "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100},
		InitialSetup: accountservice.SetupConfig{Enabled: true, Secret: "b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb28"},
		MFA:          mfaservice.Config{Enabled: true, Issuer: "Operator", ChallengeTTL: 5 * time.Minute, UserLimitPerMinute: 30, IPLimitPerMinute: 50, GlobalLimitPerMinute: 100},
		Session:      sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, SessionRefreshThreshold: time.Minute, FreshAuthTTL: 5 * time.Minute, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute},
		Password:     passwordservice.Config{ResetTokenTTL: 30 * time.Minute, ResetURL: "https://console.auth.example/reset", ResetGlobalLimit: 100},
		Capacity:     passwordservice.CapacityConfig{HashConcurrency: 1, LoginIPLimit: 30, LoginEmailLimit: 30, LoginGlobalLimit: 100},
		Retention:    accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 100, Interval: time.Minute},
	}
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "test TLS", "test TLS"
	return cfg
}

func operatorFixture(t *testing.T) (*pgxpool.Pool, realmDependencies, *config.Config) {
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
		root = filepath.Join("..", "..", "..")
	}
	read := func(path string) string {
		source, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return string(source)
	}
	for _, migration := range []string{"000001_init", "platform/000001_catalog", "platform/000002_operators"} {
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
	grants := strings.NewReplacer("auth_platform_runtime", operatorFixtureRole, "DATABASE auth_platform ", "DATABASE auth_platform_test ").Replace(read("deploy/platform-runtime-grants.sql"))
	if _, err := admin.Exec(ctx, grants); err != nil {
		t.Fatal("runtime grants", err)
	}
	pc.ConnConfig.User = operatorFixtureRole
	runtime, err := pgxpool.NewWithConfig(ctx, pc)
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
		for _, purpose := range []string{"email-verification-limit", "password-limit", "mfa-limit"} {
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
	return admin, realmDependencies{
		pool: runtime, redis: rdb, log: zap.NewNop(), scope: scope,
		hash: hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), 1),
	}, operatorConfig(realm)
}
