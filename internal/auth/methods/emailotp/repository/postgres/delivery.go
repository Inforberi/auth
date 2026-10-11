package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
)

func (r *Repository) ClaimDelivery(ctx context.Context) (*domain.Delivery, error) {
	var job domain.Delivery
	err := r.db.QueryRow(ctx, `WITH due AS (
  SELECT o.id FROM auth.email_login_outbox o
  JOIN auth.email_login_challenges c ON c.digest=o.digest JOIN auth.users u ON u.id=c.user_id
  JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=u.id
  JOIN auth.password_credentials p ON p.user_id=u.id AND p.email_id=e.id
  WHERE o.available_at<=statement_timestamp() AND o.expires_at>clock_timestamp()
  AND o.attempts<5 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
  AND c.attempts<5 AND c.expires_at>clock_timestamp()
  AND c.auth_version=u.auth_version AND e.verified_at IS NOT NULL AND u.status='active' AND u.deleted_at IS NULL
  ORDER BY o.available_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1
 ) UPDATE auth.email_login_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),
  lease_until=clock_timestamp()+interval '30 seconds' FROM due WHERE o.id=due.id
  RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *Repository) FinishDelivery(ctx context.Context, job domain.Delivery, sent bool) error {
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.email_login_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.email_login_outbox SET lease=NULL,lease_until=NULL,
  available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1)))
  WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
