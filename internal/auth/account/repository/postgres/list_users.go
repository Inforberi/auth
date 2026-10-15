package postgres

import (
	"context"
	"fmt"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) ListUsers(ctx context.Context, actor accessservice.Principal, q service.UserListQuery) ([]service.UserSummary, error) {
	args := []any{actor.UserID, actor.TokenHash, settings.UsersRead}
	where := "a.allowed AND candidate.deleted_at IS NULL"
	if q.Status != "" {
		args = append(args, q.Status)
		where += fmt.Sprintf(" AND candidate.status=$%d", len(args))
	}
	if q.Email != "" {
		args = append(args, q.Email)
		where += fmt.Sprintf(" AND candidate.id=(SELECT user_id FROM auth.user_emails WHERE email=$%d::public.citext)", len(args))
	}
	if q.BeforeCreatedAt != nil {
		args = append(args, *q.BeforeCreatedAt, q.BeforeID)
		where += fmt.Sprintf(" AND (candidate.created_at,candidate.id)<($%d::timestamptz,$%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, q.Limit+1)
	query := directoryActor + `SELECT a.allowed,u.id::text,COALESCE(u.status,''),u.created_at,p.display_name,email.email::text,(email.verified_at IS NOT NULL)
		FROM directory_actor a LEFT JOIN LATERAL (
			SELECT candidate.id,candidate.status,candidate.created_at FROM auth.users candidate WHERE ` + where + `
			ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT ` + fmt.Sprintf("$%d", len(args)) + `
		) u ON true LEFT JOIN auth.user_profile p ON p.user_id=u.id ` + directoryEmail + `
		ORDER BY u.created_at DESC,u.id DESC`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]service.UserSummary, 0, q.Limit+1)
	for rows.Next() {
		var user service.UserSummary
		var allowed bool
		var id *string
		var created *time.Time
		if err := rows.Scan(&allowed, &id, &user.Status, &created, &user.DisplayName, &user.Email, &user.EmailVerified); err != nil {
			return nil, err
		}
		if !allowed {
			return nil, accessdomain.ErrForbidden
		}
		if id != nil {
			user.ID, user.CreatedAt = domain.UserID(*id), *created
			users = append(users, user)
		}
	}
	return users, rows.Err()
}
