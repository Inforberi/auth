package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
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
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
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

func requireSessionProof(ctx context.Context, tx pgx.Tx, user domain.UserID, token string, version domain.AuthVersion, freshFor time.Duration) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM auth.sessions WHERE user_id=$1 AND token_hash=$2 AND auth_version=$3
		AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
		AND ($4::double precision=0 OR (password_verified_at<=clock_timestamp()
		AND password_verified_at>clock_timestamp()-$4::double precision*interval '1 second'))
		FOR UPDATE`, user, token, version, freshFor.Seconds()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrFreshAuthRequired
	}
	return err
}
