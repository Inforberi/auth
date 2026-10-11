package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
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
	ledger := sessionpostgres.New(db)
	params := sessionservice.CreateSessionParams{
		UserID: id, AuthVersion: 1, TokenHash: strings.Repeat("e", 64),
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour),
	}
	if err := ledger.CreateSession(ctx, params); err != nil {
		t.Fatal(err)
	}
	if err := repo.ChangePassword(ctx, id, params.TokenHash, "test-hash", "new-hash"); err != nil {
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
	if _, err := repo.FindUserByUserID(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, passworddomain.ErrNotFound) {
		t.Fatal("credential not-found contract changed")
	}
	var baseline int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateUser(ctx, "rollback@example.com", ""); err == nil {
		t.Fatal("empty hash accepted")
	}
	var users int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&users); err != nil || users != baseline {
		t.Fatal("failed registration left orphan user")
	}
}
