package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) claimInvitationDelivery(ctx context.Context) (*domain.VerificationDelivery, error) {
	job := &domain.VerificationDelivery{Invitation: true}
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT o.id FROM auth.invitation_outbox o JOIN auth.account_invitations i ON i.digest=o.digest
		JOIN auth.users u ON u.id=i.user_id
		WHERE o.available_at<=statement_timestamp() AND o.expires_at>clock_timestamp() AND o.attempts<5
		AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
		AND i.expires_at>clock_timestamp() AND u.status='pending' AND u.deleted_at IS NULL AND u.auth_version=i.auth_version
		ORDER BY o.available_at FOR UPDATE OF o SKIP LOCKED LIMIT 1
	) UPDATE auth.invitation_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds'
		FROM due WHERE o.id=due.id RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return job, err
}

func (r *Repository) finishInvitationDelivery(ctx context.Context, job domain.VerificationDelivery, sent bool) error {
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.invitation_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.invitation_outbox SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1))) WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
