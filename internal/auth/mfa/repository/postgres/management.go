package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func requireFreshMFA(ctx context.Context, tx pgx.Tx, proof service.Proof) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.role_bound_sessions s
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
		AND s.mfa_verified_at<=clock_timestamp() AND s.mfa_verified_at>clock_timestamp()-interval '5 minutes'
		AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1))`, proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return domain.ErrProofRequired
	}
	return nil
}

func (r *Repository) StepUp(ctx context.Context, proof service.Proof, replacement string, check service.Check, recovery string) (*service.StepUpCommit, error) {
	var result service.StepUpCommit
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := r.requireProof(ctx, tx, proof); err != nil {
			return err
		}
		verified, err := consumeFactor(ctx, tx, proof.UserID, check, recovery)
		if err != nil {
			return err
		}
		result.VerifiedAt = verified
		err = tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions SET token_hash=$3,mfa_verified_at=$4,
			primary_method=COALESCE(primary_method,CASE WHEN password_verified_at IS NOT NULL THEN 'password' ELSE 'emailotp' END),
			primary_verified_at=COALESCE(primary_verified_at,password_verified_at,email_reauthenticated_at)
			WHERE user_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()
			AND absolute_expires_at>clock_timestamp() RETURNING LEAST(expires_at,absolute_expires_at)`,
			proof.UserID, proof.TokenHash, replacement, verified).Scan(&result.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "mfa_step_up")
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *Repository) Disable(ctx context.Context, proof service.Proof) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		if err := r.requireProof(ctx, tx, proof); err != nil {
			return err
		}
		if err := requireFreshMFA(ctx, tx, proof); err != nil {
			return err
		}
		var required bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
			WHERE ur.user_id=$1 AND (r.system AND r.key='super_admin' OR EXISTS(SELECT 1 FROM auth.role_permissions rp
			WHERE rp.role_id=r.id AND rp.permission_key IN ('access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage','accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))))`, proof.UserID).Scan(&required)
		if err != nil {
			return err
		}
		if required {
			return domain.ErrRequiredByPolicy
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "totp_disabled")
	})
}

func (r *Repository) RegenerateRecovery(ctx context.Context, proof service.Proof, codes []string) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		if err := r.requireProof(ctx, tx, proof); err != nil {
			return err
		}
		if err := requireFreshMFA(ctx, tx, proof); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) SELECT $1,unnest($2::text[])`, proof.UserID, codes); err != nil {
			return err
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "recovery_regenerated")
	})
}

func invalidateFactors(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	for _, query := range []string{
		`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
		`DELETE FROM auth.mfa_enrollments WHERE user_id=$1`,
		`DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, user); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) CheckDisabled(ctx context.Context) error {
	var enabled bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp)`).Scan(&enabled); err != nil {
		return err
	}
	if enabled {
		return errors.New("MFA_ENABLED=false conflicts with enrolled factors; disable them through the protected API first")
	}
	return nil
}
