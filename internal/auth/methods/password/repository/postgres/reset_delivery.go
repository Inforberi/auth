package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) ClaimResetDelivery(ctx context.Context) (*domain.ResetDelivery, error) {
	var job domain.ResetDelivery
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT o.id FROM auth.password_reset_outbox o
		JOIN auth.password_resets r ON r.digest=o.digest JOIN auth.users u ON u.id=r.user_id
		WHERE o.available_at<=statement_timestamp()
		AND o.expires_at>clock_timestamp() AND o.attempts<5 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
		AND r.expires_at>clock_timestamp() AND r.auth_version=u.auth_version AND u.status='active' AND u.deleted_at IS NULL
		ORDER BY o.available_at FOR UPDATE OF o SKIP LOCKED LIMIT 1)
		UPDATE auth.password_reset_outbox o SET attempts=attempts+1,lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds'
		FROM due WHERE o.id=due.id RETURNING o.id,o.lease,o.payload,o.attempts`).Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *PasswordRepo) FinishResetDelivery(ctx context.Context, job domain.ResetDelivery, sent bool) error {
	if sent || job.Attempts >= 5 {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.password_reset_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.password_reset_outbox SET lease=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1))) WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
