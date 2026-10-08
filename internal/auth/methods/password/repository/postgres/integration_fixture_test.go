package postgres

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func schemaFixture(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTH_SCHEMA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("explicit disposable schema database not configured")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/auth_schema_test" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.User == nil || u.User.Username() != "auth_schema_test" {
		t.Fatal("schema check requires the dedicated localhost auth_schema_test fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := pgxpool.New(ctx, dsn)
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
}
