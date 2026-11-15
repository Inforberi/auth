package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type MutationAuthority interface {
	AuthorizeMutation(context.Context, pgx.Tx, operatordomain.Principal, operatordomain.Permission, time.Duration) (time.Time, error)
}

func NewManaged(db *pgxpool.Pool, authority MutationAuthority, freshFor time.Duration, creation domain.CreationPolicy) (*Repository, error) {
	if db == nil || authority == nil || freshFor < time.Minute || freshFor > 15*time.Minute || !creation.Valid() {
		return nil, domain.ErrUnavailable
	}
	return &Repository{db: db, authority: authority, freshFor: freshFor, creation: creation}, nil
}

func (r *Repository) ApplyTransition(ctx context.Context, actor operatordomain.Principal, command domain.Transition) (domain.TransitionReceipt, error) {
	var result domain.TransitionReceipt
	err := r.mutate(ctx, actor, operatordomain.ProjectsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		if command.Action == domain.Resume {
			var project domain.ID
			if err := tx.QueryRow(ctx, `SELECT id FROM platform.projects WHERE id=$1 FOR UPDATE`, command.ProjectID).Scan(&project); err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
			if err := guardDeletion(ctx, tx, command.ProjectID); err != nil {
				return err
			}
		}
		command.ActorID, command.ActorKind = domain.ID(actor.UserID), domain.OperatorActor
		var err error
		result, err = Transition(ctx, tx, command)
		return err
	})
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	return result, nil
}

func (r *Repository) mutate(ctx context.Context, actor operatordomain.Principal, permission operatordomain.Permission, apply func(context.Context, pgx.Tx, time.Time) error) error {
	if r.authority == nil || r.db == nil {
		return domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the original error; Commit closes the transaction.
	}()
	deadline, err := r.authority.AuthorizeMutation(ctx, tx, actor, permission, r.freshFor)
	if err != nil {
		return err
	}
	if permission == operatordomain.SettingsManage {
		if err := settingspostgres.RequireAPISettings(ctx, tx); err != nil {
			return err
		}
	}
	if err := apply(ctx, tx, deadline); err != nil {
		return err
	}
	// Waiting for the project lock must not extend the proof/session validity window.
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !fresh {
		return operatordomain.ErrFreshAuthRequired
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return nil
}
