package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func (r *Repository) ClaimRecoveryDelivery(ctx context.Context) (*domain.RecoveryDelivery, error) {
	var job domain.RecoveryDelivery
	err := r.db.QueryRow(ctx, `WITH due AS (
		SELECT id,attempts FROM auth.mfa_recovery_outbox
		WHERE failed_at IS NULL AND available_at<=statement_timestamp()
		AND (lease_until IS NULL OR lease_until<=clock_timestamp())
		ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE auth.mfa_recovery_outbox o SET attempts=LEAST(5,o.attempts+1),
		lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds'
		FROM due WHERE o.id=due.id RETURNING o.id,o.lease,o.payload,o.attempts,due.attempts>=5`).
		Scan(&job.ID, &job.Lease, &job.Payload, &job.Attempts, &job.Exhausted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (r *Repository) FinishRecoveryDelivery(ctx context.Context, job domain.RecoveryDelivery, sent bool) error {
	if sent {
		_, err := r.db.Exec(ctx, `DELETE FROM auth.mfa_recovery_outbox WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
		return err
	}
	_, err := r.db.Exec(ctx, `UPDATE auth.mfa_recovery_outbox SET lease=NULL,lease_until=NULL,
		failed_at=CASE WHEN attempts>=5 THEN clock_timestamp() END,
		available_at=clock_timestamp()+make_interval(secs=>LEAST(300,30*power(2,attempts-1)))
		WHERE id=$1 AND lease=$2`, job.ID, job.Lease)
	return err
}
