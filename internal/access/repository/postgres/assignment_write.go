package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// ReadRoleInTransaction shares the current snapshot under the caller's Access lock.
func ReadRoleInTransaction(ctx context.Context, tx pgx.Tx, role domain.RoleID) (domain.Role, error) {
	return readRole(ctx, tx, role)
}

// ApplyAssignmentInTransaction owns persistence only. The caller holds Access
// and target-user locks, validates authority/versions/system policy, and owns audit/commit.
func ApplyAssignmentInTransaction(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, role domain.RoleID, grant bool, version int64) (int64, bool, error) {
	if grant {
		var full bool
		if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2)
			AND (SELECT count(*) FROM (SELECT 1 FROM auth.user_roles WHERE user_id=$1 LIMIT $3) bounded)>=$3`, user, role, domain.MaxUserRoles).Scan(&full); err != nil {
			return 0, false, err
		}
		if full {
			return 0, false, domain.ErrConflict
		}
	}
	query := `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`
	if grant {
		query = `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`
	}
	result, err := tx.Exec(ctx, query, user, role)
	if err != nil {
		return 0, false, err
	}
	if result.RowsAffected() == 0 {
		return version, false, nil
	}
	// Grants invalidate pre-grant active sessions. Pending activation credentials
	// remain valid; revocations take effect through the current SQL permissions.
	err = tx.QueryRow(ctx, `UPDATE auth.users SET access_version=access_version+1,
		auth_version=auth_version+CASE WHEN $2 AND status='active' THEN 1 ELSE 0 END
		WHERE id=$1 RETURNING access_version`, user, grant).Scan(&version)
	return version, true, err
}
