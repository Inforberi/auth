package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func checkConcurrentRegistration(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := repo.CreateUser(ctx, "race@example.com", "hash")
			results <- err
		}()
	}
	close(start)
	success, duplicate := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			success++
		case errors.Is(err, passwordmodel.ErrEmailAlreadyExists):
			duplicate++
		default:
			t.Fatalf("unexpected concurrent registration result: %v", err)
		}
	}
	if success != 1 || duplicate != 1 {
		t.Fatal("registration is not uniquely owned")
	}
	var orphans int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM auth.users u LEFT JOIN auth.password_credentials p ON p.user_id=u.id WHERE p.user_id IS NULL`).Scan(&orphans); err != nil || orphans != 0 {
		t.Fatal("duplicate registration left orphan user")
	}
}
