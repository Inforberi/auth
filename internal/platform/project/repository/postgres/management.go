package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type MutationAuthority interface {
	AuthorizeMutation(context.Context, pgx.Tx, operatordomain.Principal, operatordomain.Permission, time.Duration) (time.Time, error)
}

func NewManaged(db *pgxpool.Pool, authority MutationAuthority, freshFor time.Duration) (*Repository, error) {
	if db == nil || authority == nil || freshFor < time.Minute || freshFor > 15*time.Minute {
		return nil, domain.ErrUnavailable
	}
	return &Repository{db: db, authority: authority, freshFor: freshFor}, nil
}

func (r *Repository) ApplyTransition(ctx context.Context, actor operatordomain.Principal, command domain.Transition) (domain.TransitionReceipt, error) {
	if r.authority == nil || r.db == nil {
		return domain.TransitionReceipt{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.TransitionReceipt{}, catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the original error; Commit closes the transaction.
	}()
	deadline, err := r.authority.AuthorizeMutation(ctx, tx, actor, operatordomain.ProjectsManage, r.freshFor)
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	// Attribution is derived here too: the SQL port never trusts a caller-supplied actor/action kind.
	command.ActorID, command.ActorKind = domain.ID(actor.UserID), domain.OperatorActor
	result, err := Transition(ctx, tx, command)
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	// Waiting for the project lock must not extend the proof/session validity window.
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return domain.TransitionReceipt{}, catalogError(ctx, err)
	}
	if !fresh {
		return domain.TransitionReceipt{}, operatordomain.ErrFreshAuthRequired
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TransitionReceipt{}, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return result, nil
}
