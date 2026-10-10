package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	migrateFixture(t, db, ctx, "down")
	var present bool
	if err := db.QueryRow(ctx, "SELECT to_regnamespace('auth') IS NOT NULL").Scan(&present); err != nil || present {
		t.Fatal("down did not remove auth schema")
	}
	migrateFixture(t, db, ctx, "up")
	repo := New(db)
	t.Run("password recovery", func(t *testing.T) { checkRecovery(t, db, ctx) })
	t.Run("email verification", func(t *testing.T) { checkVerification(t, db, ctx) })
	t.Run("repository", func(t *testing.T) { checkRepository(t, db, ctx, repo) })
	t.Run("constraints", func(t *testing.T) { checkConstraints(t, db, ctx, repo) })
	t.Run("concurrent registration", func(t *testing.T) { checkConcurrentRegistration(t, db, ctx, repo) })
	t.Run("session management", func(t *testing.T) { checkSessionManagement(t, db, ctx) })
	t.Run("account status", func(t *testing.T) { checkAccountStatus(t, db, ctx) })
	t.Run("email change", func(t *testing.T) { checkEmailChange(t, db, ctx) })
	t.Run("protected recovery", func(t *testing.T) { checkProtectedRecovery(t, db, ctx) })
	t.Run("protected recovery races", func(t *testing.T) { checkProtectedRecoveryRaces(t, db, ctx) })
	t.Run("protected recovery delivery", func(t *testing.T) { checkProtectedRecoveryDelivery(t, db, ctx) })
	t.Run("account deletion", func(t *testing.T) { checkAccountDeletion(t, db, ctx) })
}

func expectSQLState(t *testing.T, db *pgxpool.Pool, ctx context.Context, code, sql string, args ...any) {
	t.Helper()
	_, err := db.Exec(ctx, sql, args...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}
