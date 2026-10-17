package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

const freshManagementPrimary = `(s.password_verified_at<=clock_timestamp()
	AND s.password_verified_at>clock_timestamp()-interval '5 minutes')
	OR ($4 AND s.email_reauthenticated_at<=clock_timestamp()
		AND s.email_reauthenticated_at>clock_timestamp()-interval '5 minutes'
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL)
		AND EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1)
		AND EXISTS(SELECT 1 FROM auth.user_emails e WHERE e.user_id=$1
			AND e.id=s.email_reauthenticated_id AND e.verified_at IS NOT NULL))`

const administrativeMFARequired = `EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
	WHERE ur.user_id=$1 AND (r.system AND r.key='super_admin' OR EXISTS(SELECT 1 FROM auth.role_permissions rp
	WHERE rp.role_id=r.id AND rp.permission_key IN ('access.roles.manage','access.assignments.manage','accounts.email.bind','accounts.users.manage','accounts.users.status.manage','accounts.users.delete','auth.settings.manage'))))`

func (r *Repository) Status(ctx context.Context, proof service.Proof) (*service.SecurityStatus, error) {
	var result service.SecurityStatus
	err := r.db.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1),auth.role_requires_mfa($1),
		`+administrativeMFARequired+`,
		(SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id=$1),
		EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1 AND verified_at IS NOT NULL),
		EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1),
		COALESCE((`+freshManagementPrimary+`),false),
		COALESCE(s.mfa_verified_at<=statement_timestamp() AND s.mfa_verified_at>statement_timestamp()-interval '5 minutes'
			AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1),false)
		FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
		AND u.status='active' AND u.deleted_at IS NULL AND s.revoked_at IS NULL
		AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()`,
		proof.UserID, proof.TokenHash, proof.AuthVersion, r.emailProofEnabled).Scan(
		&result.TOTPEnabled, &result.RequiredByRole, &result.RequiredByAdministration,
		&result.RecoveryCodesRemaining, &result.VerifiedEmail, &result.PasswordConfigured,
		&result.FreshPrimaryProof, &result.FreshMFAProof,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrProofRequired
	}
	if err != nil {
		return nil, err
	}
	result.EmailReauthenticationEnabled = r.emailProofEnabled
	return &result, nil
}
