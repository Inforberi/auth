package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type Repository struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func (r *Repository) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit closes the transaction.
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func requireProof(ctx context.Context, tx pgx.Tx, proof service.Proof) error {
	var version int64
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1
		AND status='active' AND deleted_at IS NULL FOR UPDATE`, proof.UserID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && version != proof.AuthVersion) {
		return domain.ErrProofRequired
	}
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT id FROM auth.sessions WHERE user_id=$1 AND token_hash=$2 AND auth_version=$3
		AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
		AND password_verified_at<=clock_timestamp()
		AND password_verified_at>clock_timestamp()-interval '5 minutes' FOR UPDATE`, proof.UserID, proof.TokenHash, version).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrProofRequired
	}
	return err
}

func audit(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.mfa_audit(user_id,event) VALUES ($1,$2)`, user, event)
	return err
}
