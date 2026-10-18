package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
)

func (r *Repository) List(ctx context.Context, q service.ListQuery) (service.Page, error) {
	if q.Limit < 1 || q.Limit > 100 || (q.Phase != "" && !q.Phase.Valid()) ||
		(q.Before != nil && (q.Before.CreatedAt.IsZero() || !domain.ValidID(q.Before.ID))) {
		return service.Page{}, domain.ErrInvalidPage
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	where := "true"
	args := make([]any, 0, 4)
	if q.Phase != "" {
		args = append(args, q.Phase)
		where = "phase=$1"
	}
	if q.Before != nil {
		args = append(args, q.Before.CreatedAt, q.Before.ID)
		where += fmt.Sprintf(" AND (created_at,id)<($%d::timestamptz,$%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	rows, err := r.db.Query(ctx, `SELECT `+projectColumns+` FROM platform.projects WHERE `+where+
		fmt.Sprintf(` ORDER BY created_at DESC,id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return service.Page{}, catalogError(ctx, err)
	}
	defer rows.Close()
	page := service.Page{Projects: make([]domain.Project, 0, q.Limit+1)}
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return service.Page{}, catalogError(ctx, err)
		}
		page.Projects = append(page.Projects, project)
	}
	if err := rows.Err(); err != nil {
		return service.Page{}, catalogError(ctx, err)
	}
	if len(page.Projects) > q.Limit {
		page.Projects = page.Projects[:q.Limit]
		last := page.Projects[len(page.Projects)-1]
		page.Next = &service.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}
