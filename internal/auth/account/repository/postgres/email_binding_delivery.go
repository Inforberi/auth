package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) claimBindingDelivery(ctx context.Context) (*domain.VerificationDelivery, error) {
	job := domain.VerificationDelivery{EmailBinding: true}
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT b.id FROM auth.email_bindings b JOIN auth.users u ON u.id=b.user_id
		JOIN auth.users a ON a.id=b.actor_id
		JOIN auth.role_bound_sessions s ON s.user_id=a.id AND s.token_hash=b.actor_session_hash AND s.auth_version=a.auth_version
		WHERE b.delivered_at IS NULL AND b.available_at<=statement_timestamp() AND b.expires_at>clock_timestamp()
		AND b.delivery_attempts<5 AND b.attempts<5 AND (b.lease_until IS NULL OR b.lease_until<=clock_timestamp())
		AND u.status='active' AND u.deleted_at IS NULL AND u.auth_version=b.auth_version
		AND a.status='active' AND a.deleted_at IS NULL AND s.revoked_at IS NULL
		AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		AND s.password_verified_at<=clock_timestamp() AND s.password_verified_at>clock_timestamp()-interval '5 minutes'
		AND s.mfa_verified_at<=clock_timestamp() AND s.mfa_verified_at>clock_timestamp()-interval '5 minutes'
		AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=a.id)
		AND EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions p ON p.role_id=ur.role_id
			WHERE ur.user_id=a.id AND p.permission_key=$1)
		ORDER BY b.available_at,b.id FOR UPDATE OF b SKIP LOCKED LIMIT 1
	) UPDATE auth.email_bindings b SET delivery_attempts=delivery_attempts+1,lease=gen_random_uuid(),
		lease_until=clock_timestamp()+interval '30 seconds' FROM due WHERE b.id=due.id
		RETURNING b.id,b.lease,b.payload,b.delivery_attempts`, settings.EmailBindingManage).
		Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *Repository) finishBindingDelivery(ctx context.Context, job domain.VerificationDelivery, sent bool) error {
	if sent {
		_, err := r.db.Exec(ctx, `UPDATE auth.email_bindings SET delivered_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.email_bindings SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,delivery_attempts-1))) WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
