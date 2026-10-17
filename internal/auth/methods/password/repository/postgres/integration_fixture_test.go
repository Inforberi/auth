package postgres

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func schemaFixture(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	return schemaFixtureDSN(t, os.Getenv("AUTH_SCHEMA_TEST_DATABASE_URL"), 60*time.Second)
}

func schemaFixtureDSN(t *testing.T, dsn string, timeout time.Duration) (*pgxpool.Pool, context.Context) {
	t.Helper()
	if dsn == "" {
		t.Skip("explicit disposable schema database not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/auth_schema_test" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.User == nil || u.User.Username() != "auth_schema_test" {
		t.Fatal("schema check requires the dedicated localhost auth_schema_test fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 10
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var present bool
	if err := db.QueryRow(ctx, "SELECT to_regnamespace('auth') IS NOT NULL").Scan(&present); err != nil || present {
		t.Fatal("fixture must be a fresh database without auth schema")
	}
	return db, ctx
}

func migrateFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, direction string) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "..", "..", "migrations", "000001_init."+direction+".sql")
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("%s migration: %v", direction, err)
	}
	if direction == "up" {
		_, err := settingspostgres.New(db).Initialize(ctx, settingsdomain.Policy{
			Methods:      settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true},
			Registration: settingsdomain.PublicRegistration{Enabled: true, Google: true, Telegram: true}, PasswordEmailVerification: settingsdomain.VerificationOptional,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
