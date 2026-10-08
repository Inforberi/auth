package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func checkRepository(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo) {
	t.Helper()
	id, err := repo.CreateUser(ctx, "alice@example.com", "test-hash")
	if err != nil {
		t.Fatal(err)
	}
	row, err := repo.FindByEmail(ctx, "ALICE@EXAMPLE.COM")
	if err != nil || row.UserID != id || row.PasswordHash != "test-hash" {
		t.Fatalf("credential lookup failed: %v", err)
	}
	exists, err := repo.ExistsByEmail(ctx, "ALICE@EXAMPLE.COM")
	if err != nil || !exists {
		t.Fatal("case-insensitive ownership missing")
	}
	var user accountdomain.User
	if err := db.QueryRow(ctx, `SELECT id,status,auth_version,created_at,updated_at,deleted_at FROM auth.users WHERE id=$1`, id).Scan(
		&user.ID, &user.Status, &user.AuthVersion, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
		t.Fatal(err)
	}
	if user.Status != accountdomain.StatusActive || user.AuthVersion != 1 || user.DeletedAt != nil {
		t.Fatal("invalid account defaults")
	}
	var before, after time.Time
	if err := db.QueryRow(ctx, `SELECT updated_at FROM auth.password_credentials WHERE user_id=$1`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdatePasswordHash(ctx, id, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT updated_at FROM auth.password_credentials WHERE user_id=$1`, id).Scan(&after); err != nil || !after.After(before) {
		t.Fatal("updated_at not maintained")
	}
	password, err := repo.FindUserByUserID(ctx, id)
	if err != nil || password.PasswordHash != "new-hash" {
		t.Fatalf("password update failed: %v", err)
	}
	if _, err := repo.FindByEmail(ctx, "unknown@example.com"); !errors.Is(err, passworddomain.ErrUserNotFound) {
		t.Fatal("not-found contract changed")
	}
	if err := repo.UpdatePasswordHash(ctx, "00000000-0000-0000-0000-000000000000", "hash"); !errors.Is(err, passworddomain.ErrNotFound) {
		t.Fatal("update not-found contract changed")
	}
	if _, err := repo.CreateUser(ctx, "rollback@example.com", ""); err == nil {
		t.Fatal("empty hash accepted")
	}
	var orphans int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users u LEFT JOIN auth.password_credentials p ON p.user_id=u.id WHERE p.user_id IS NULL`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatal("failed registration left orphan user")
	}
}
