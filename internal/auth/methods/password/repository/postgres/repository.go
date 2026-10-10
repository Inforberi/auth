package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type PasswordRepo struct {
	db           *pgxpool.Pool
	registration func(context.Context, pgx.Tx, accountdomain.UserID, accountdomain.AddressID, string) error
}

func NewWithRegistration(db *pgxpool.Pool, queue func(context.Context, pgx.Tx, accountdomain.UserID, accountdomain.AddressID, string) error) *PasswordRepo {
	return &PasswordRepo{db: db, registration: queue}
}

func New(db *pgxpool.Pool) *PasswordRepo {
	return &PasswordRepo{db: db}
}

func (r *PasswordRepo) transaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit closes the transaction.
	}()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
