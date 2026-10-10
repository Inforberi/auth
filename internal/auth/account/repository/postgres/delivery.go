package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ClaimDelivery(ctx context.Context) (*domain.VerificationDelivery, error) {
	changeFirst := r.emailChangeDelivery && r.deliveryTurn.Add(1)%2 == 1
	if changeFirst {
		job, err := r.claimChangeDelivery(ctx)
		if err != nil || job != nil {
			return job, err
		}
	}
	var job domain.VerificationDelivery
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT o.id FROM auth.email_verification_outbox o
		JOIN auth.email_verifications v ON v.digest=o.digest
		JOIN auth.user_emails e ON e.id=v.email_id JOIN auth.users u ON u.id=e.user_id
		WHERE o.available_at<=statement_timestamp()
		AND o.expires_at>clock_timestamp() AND o.attempts<5 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
		AND v.expires_at>clock_timestamp() AND e.verified_at IS NULL AND u.status='active' AND u.deleted_at IS NULL
		ORDER BY o.available_at FOR UPDATE OF o SKIP LOCKED LIMIT 1
	) UPDATE auth.email_verification_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),
		lease_until=clock_timestamp()+interval '30 seconds' FROM due WHERE o.id=due.id
		RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		if r.emailChangeDelivery && !changeFirst {
			return r.claimChangeDelivery(ctx)
		}
		return nil, nil
	}
	return &job, err
}

func (r *Repository) FinishDelivery(ctx context.Context, job domain.VerificationDelivery, sent bool) error {
	if job.EmailChange {
		return r.finishChangeDelivery(ctx, job, sent)
	}
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.email_verification_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.email_verification_outbox SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1)))
		WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
