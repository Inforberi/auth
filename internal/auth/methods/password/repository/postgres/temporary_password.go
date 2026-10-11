package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type TemporaryPasswordRepo struct {
	*PasswordRepo
	provision func(context.Context, pgx.Tx, accountservice.ProvisionCommand) (*accountservice.ProvisionResult, error)
}

func NewTemporaryPassword(db *pgxpool.Pool, provision func(context.Context, pgx.Tx, accountservice.ProvisionCommand) (*accountservice.ProvisionResult, error)) *TemporaryPasswordRepo {
	return &TemporaryPasswordRepo{PasswordRepo: New(db), provision: provision}
}

func lockTemporaryUser(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	var found accountdomain.UserID
	err := tx.QueryRow(ctx, `SELECT id FROM auth.users WHERE id=$1 AND status='pending' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&found)
	return temporaryError(err)
}

func temporaryError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrInvalidTemporaryPassword
	}
	return err
}
