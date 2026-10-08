package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func checkConstraints(t *testing.T, db *pgxpool.Pool, ctx context.Context, repo *PasswordRepo) {
	t.Helper()
	id, err := repo.CreateUser(ctx, "owner@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateUser(ctx, "other@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	var emailID string
	if err := db.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email) VALUES ($1,'second@example.com') RETURNING id`, other).Scan(&emailID); err != nil {
		t.Fatal(err)
	}
	expectSQLState(t, db, ctx, "23503", `UPDATE auth.password_credentials SET email_id=$2 WHERE user_id=$1`, id, emailID)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.users SET status='admin' WHERE id=$1`, id)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.users SET auth_version=0 WHERE id=$1`, id)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.users SET deleted_at=now() WHERE id=$1`, id)
	expectSQLState(t, db, ctx, "23514", `INSERT INTO auth.user_emails(user_id,email) VALUES ($1,' invalid@example.com ')`, id)
	expectSQLState(t, db, ctx, "23514", `UPDATE auth.user_profile SET phone_number='invalid' WHERE user_id=$1`, id)
	if _, err := db.Exec(ctx, `UPDATE auth.user_profile SET phone_number='+12345678901' WHERE user_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE auth.users SET status='blocked',deleted_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateUser(ctx, "owner@example.com", "hash"); !errors.Is(err, passworddomain.ErrEmailAlreadyExists) {
		t.Fatal("deleted account lost email ownership")
	}
	if _, err := db.Exec(ctx, `DELETE FROM auth.users WHERE id=$1`, other); err != nil {
		t.Fatal(err)
	}
	var dangling int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.user_emails WHERE user_id=$1) + (SELECT count(*) FROM auth.password_credentials WHERE user_id=$1) + (SELECT count(*) FROM auth.user_profile WHERE user_id=$1)`, other).Scan(&dangling); err != nil || dangling != 0 {
		t.Fatalf("cascade failed: %v", err)
	}
}
