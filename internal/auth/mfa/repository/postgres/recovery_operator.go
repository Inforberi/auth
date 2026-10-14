package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) RecoveryTarget(ctx context.Context, user accountdomain.UserID, request string) (*service.RecoveryTarget, error) {
	var result service.RecoveryTarget
	err := r.db.QueryRow(ctx, `SELECT current_database(),session_user::text,c.state,c.auth_version,c.expires_at
		FROM auth.mfa_recovery_requests c JOIN auth.users u ON u.id=c.user_id
		WHERE c.user_id=$1 AND c.request_id=$2 AND c.auth_version=u.auth_version AND c.state<>'cancelled'
		AND c.expires_at>clock_timestamp() AND u.status='active' AND u.deleted_at IS NULL
		AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname='auth_mfa_recovery_operator'
		AND pg_catalog.pg_has_role(session_user,g.oid,'MEMBER'))`, user, request).
		Scan(&result.Database, &result.Operator, &result.State, &result.AuthVersion, &result.ExpiresAt)
	if err != nil {
		return nil, recoveryOperatorError(err)
	}
	return &result, nil
}

func (r *Repository) DecideRecovery(ctx context.Context, input domain.RecoveryDecision) error {
	var accepted bool
	err := r.db.QueryRow(ctx, `SELECT auth.decide_mfa_recovery($1,$2,$3,$4,$5,$6)`,
		input.UserID, input.RequestID, input.ExpectedVersion, input.Approve, input.Environment, input.Reason).Scan(&accepted)
	if err != nil {
		return recoveryOperatorError(err)
	}
	if !accepted {
		return domain.ErrRecoveryOperatorDenied
	}
	return nil
}

func recoveryOperatorError(err error) error {
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "42501") {
		return domain.ErrRecoveryOperatorDenied
	}
	return err
}
