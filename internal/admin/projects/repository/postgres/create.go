package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

func (r *Repository) Create(ctx context.Context, actor operatordomain.Principal, input domain.Create) (domain.CreationReceipt, error) {
	var result domain.CreationReceipt
	err := r.mutate(ctx, actor, operatordomain.ProjectsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		command, err := input.Normalize()
		if err != nil {
			return err
		}
		// Same-operation retries serialize, not unrelated project creation. Hash collisions only delay.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform.project.create:'||$1::text,0))`, command.OperationID); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if receipt, found, err := readCreation(ctx, tx, actor, command); found || err != nil {
			result = receipt
			return err
		}
		origin, err := r.creation.Origin(command.Slug)
		if err != nil {
			return err
		}
		p := &result.Project
		err = tx.QueryRow(ctx, `WITH project AS (
			INSERT INTO platform.projects(id,slug,name,origin,storage_target)
			VALUES(gen_random_uuid(),$1,$2,$3,$4) RETURNING id,slug,name,origin,storage_target,created_at
		) INSERT INTO platform.project_creations(operation_id,project_id,actor_id,slug,name,origin,storage_target,reason,created_at)
			SELECT $5,id,$6,slug,name,origin,storage_target,$7,created_at FROM project
			RETURNING project_id::text,slug,name,origin,created_at`, command.Slug, command.Name, origin, r.creation.StorageTarget,
			command.OperationID, actor.UserID, command.Reason).Scan(&p.ID, &p.Slug, &p.Name, &p.Origin, &p.CreatedAt)
		var conflict *pgconn.PgError
		if errors.As(err, &conflict) && conflict.Code == "23505" {
			return domain.ErrConflict
		}
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		setCreationState(p)
		return nil
	})
	if err != nil {
		return domain.CreationReceipt{}, err
	}
	return result, nil
}

func readCreation(ctx context.Context, tx pgx.Tx, actor operatordomain.Principal, command domain.Create) (domain.CreationReceipt, bool, error) {
	result := domain.CreationReceipt{Replayed: true}
	var matches bool
	p := &result.Project
	err := tx.QueryRow(ctx, `SELECT project_id::text,slug,name,origin,created_at,
		actor_id=$2 AND slug=$3 AND name=$4 AND reason=$5 FROM platform.project_creations WHERE operation_id=$1`,
		command.OperationID, actor.UserID, command.Slug, command.Name, command.Reason).Scan(&p.ID, &p.Slug, &p.Name, &p.Origin, &p.CreatedAt, &matches)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.CreationReceipt{}, false, nil
	}
	if err != nil {
		return domain.CreationReceipt{}, false, sqlerrors.Catalog(ctx, err)
	}
	if !matches {
		return domain.CreationReceipt{}, true, domain.ErrConflict
	}
	setCreationState(p)
	return result, true, nil
}

func setCreationState(p *domain.Project) {
	p.DesiredState, p.Phase, p.Version, p.Generation, p.UpdatedAt = domain.Enabled, domain.Pending, 1, 1, p.CreatedAt
}
