package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ListOperators(ctx context.Context, actor domain.Principal, after accountdomain.UserID) ([]domain.Operator, error) {
	if !actor.Valid() {
		return nil, domain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `WITH authority AS (
		SELECT first_operator_id FROM platform.operator_realm WHERE id=$1 AND first_operator_id=$2 AND `+operatorReadGuard+`
	)
	SELECT u.id,COALESCE((SELECT email FROM auth.user_emails WHERE user_id=u.id ORDER BY id LIMIT 1),''),
		u.status,ARRAY(SELECT permission_key FROM platform.operator_permissions WHERE user_id=u.id ORDER BY permission_key),
		u.id=a.first_operator_id
	FROM authority a CROSS JOIN auth.users u
	WHERE ($5::uuid IS NULL OR u.id>$5) AND (
		EXISTS(SELECT 1 FROM platform.operator_permissions WHERE user_id=u.id)
		OR EXISTS(SELECT 1 FROM platform.operator_management WHERE user_id=u.id AND action='invite')
	)
	ORDER BY u.id LIMIT 50`,
		r.realm, actor.UserID, actor.TokenHash, domain.OperatorsManage, nullableOperator(after))
	if err != nil {
		return nil, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	defer rows.Close()
	items := make([]domain.Operator, 0)
	for rows.Next() {
		var item domain.Operator
		if err := rows.Scan(&item.UserID, &item.Email, &item.Status, &item.Permissions, &item.Owner); err != nil {
			return nil, errors.Join(domain.ErrUnavailable, ctx.Err())
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return items, nil
}
