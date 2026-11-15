package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

func (r *Repository) Rename(ctx context.Context, actor operatordomain.Principal, command domain.Rename) (domain.NameReceipt, error) {
	var result domain.NameReceipt
	err := r.mutate(ctx, actor, operatordomain.ProjectsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var name string
		var version int64
		var phase domain.Phase
		if err := tx.QueryRow(ctx, `SELECT name,version,phase FROM platform.projects WHERE id=$1 FOR UPDATE`, command.ProjectID).Scan(&name, &version, &phase); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var matches bool
		err := tx.QueryRow(ctx, `SELECT name,version,actor_id=$3 AND name=$4 AND reason=$5 AND expected_version=$6
			FROM platform.project_name_changes WHERE project_id=$1 AND operation_id=$2`,
			command.ProjectID, command.OperationID, actor.UserID, command.Name, command.Reason, command.ExpectedVersion).
			Scan(&result.Name, &result.Version, &matches)
		if err == nil {
			if !matches {
				return domain.ErrConflict
			}
			result.Replayed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return sqlerrors.Catalog(ctx, err)
		}
		if err := guardDeletion(ctx, tx, command.ProjectID); err != nil {
			return err
		}
		if version != command.ExpectedVersion || phase == domain.Provisioning {
			return domain.ErrConflict
		}
		if name != command.Name {
			err = tx.QueryRow(ctx, `UPDATE platform.projects SET name=$2,version=version+1,updated_at=GREATEST(updated_at,clock_timestamp())
				WHERE id=$1 RETURNING version`, command.ProjectID, command.Name).Scan(&version)
			if err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO platform.project_name_changes(project_id,operation_id,actor_id,previous_name,name,reason,expected_version,version)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, command.ProjectID, command.OperationID, actor.UserID, name, command.Name, command.Reason, command.ExpectedVersion, version)
		result = domain.NameReceipt{Name: command.Name, Version: version}
		return sqlerrors.Catalog(ctx, err)
	})
	if err != nil {
		return domain.NameReceipt{}, err
	}
	return result, nil
}
