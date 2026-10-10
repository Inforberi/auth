package postgres

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db                  *pgxpool.Pool
	deliveryTurn        atomic.Uint64
	emailChangeDelivery bool
	invitationDelivery  bool
}

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewWithEmailChanges(db *pgxpool.Pool) *Repository {
	return &Repository{db: db, emailChangeDelivery: true}
}

func NewWithDelivery(db *pgxpool.Pool, emailChanges, invitations bool) *Repository {
	return &Repository{db: db, emailChangeDelivery: emailChanges, invitationDelivery: invitations}
}

func (r *Repository) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; preserve its original error.
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
