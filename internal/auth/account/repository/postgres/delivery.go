package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ClaimDelivery(ctx context.Context) (*domain.VerificationDelivery, error) {
	if _, err := r.db.Exec(ctx, `DELETE FROM auth.email_verifications v USING auth.user_emails e,auth.users u
		WHERE v.email_id=e.id AND e.user_id=u.id AND
		(v.expires_at<=clock_timestamp() OR e.verified_at IS NOT NULL OR u.status<>'active' OR u.deleted_at IS NOT NULL)`); err != nil {
		return nil, err
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM auth.email_verification_outbox WHERE attempts>=5 AND (lease_until IS NULL OR lease_until<=clock_timestamp())`); err != nil {
		return nil, err
	}
	var job domain.VerificationDelivery
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT id FROM auth.email_verification_outbox WHERE available_at<=clock_timestamp()
		AND expires_at>clock_timestamp() AND attempts<5 AND (lease_until IS NULL OR lease_until<=clock_timestamp())
		ORDER BY available_at FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE auth.email_verification_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),
		lease_until=clock_timestamp()+interval '30 seconds' FROM due WHERE o.id=due.id
		RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *Repository) FinishDelivery(ctx context.Context, job domain.VerificationDelivery, sent bool) error {
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.email_verification_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.email_verification_outbox SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1)))
		WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
