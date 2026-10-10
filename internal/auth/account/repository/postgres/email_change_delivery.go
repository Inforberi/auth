package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) claimChangeDelivery(ctx context.Context) (*domain.VerificationDelivery, error) {
	var job domain.VerificationDelivery
	job.EmailChange = true
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT o.id FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id
		WHERE o.available_at<=statement_timestamp() AND o.expires_at>clock_timestamp() AND o.attempts<5
		AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
		AND (o.kind<>'confirm' OR (c.state='pending' AND c.expires_at>clock_timestamp()))
		AND (o.kind<>'recovery' OR (c.state='reported' AND c.recovery_expires_at>clock_timestamp()
			AND EXISTS(SELECT 1 FROM auth.users u WHERE u.id=c.user_id AND u.status='blocked'
			AND u.deleted_at IS NULL AND u.auth_version=c.recovery_version)))
		ORDER BY o.available_at FOR UPDATE OF o SKIP LOCKED LIMIT 1
	) UPDATE auth.email_change_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),
		lease_until=clock_timestamp()+interval '30 seconds' FROM due WHERE o.id=due.id
		RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *Repository) finishChangeDelivery(ctx context.Context, job domain.VerificationDelivery, sent bool) error {
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.email_change_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.email_change_outbox SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1))) WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
