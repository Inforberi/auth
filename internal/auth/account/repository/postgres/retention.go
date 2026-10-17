package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

const retentionBatchSize = 100

func (r *Repository) PurgeRetention(ctx context.Context, cfg service.RetentionConfig) (int64, error) {
	var removed int64
	batch := cfg.BatchSize
	if batch == 0 {
		batch = retentionBatchSize
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		// Lock users before contacts, matching deletion/verification lock order.
		// CTEs share a snapshot: subtract RETURNING IDs before marking the reservation released.
		var contacts int64
		if err := tx.QueryRow(ctx, `WITH owners AS MATERIALIZED (
			SELECT u.id FROM auth.users u
			WHERE u.deleted_at <= statement_timestamp()-$1::double precision*interval '24 hours'
			AND NOT u.email_reuse_blocked AND u.email_released_at IS NULL
			ORDER BY u.deleted_at,u.id LIMIT $2 FOR UPDATE OF u SKIP LOCKED
		), contacts AS MATERIALIZED (
			SELECT e.id FROM auth.user_emails e JOIN owners u ON u.id=e.user_id
			ORDER BY e.user_id,e.id LIMIT $2 FOR UPDATE OF e SKIP LOCKED
		), removed AS (
			DELETE FROM auth.user_emails e USING contacts c WHERE e.id=c.id RETURNING e.id
		), released AS (
			UPDATE auth.users u SET email_released_at=clock_timestamp() FROM owners o
			WHERE u.id=o.id AND NOT EXISTS (
				SELECT 1 FROM auth.user_emails e WHERE e.user_id=u.id
				AND e.id NOT IN (SELECT id FROM removed)
			) RETURNING u.id
		)
		SELECT count(*) FROM removed`, cfg.EmailReservationDays, batch).Scan(&contacts); err != nil {
			return err
		}
		removed += contacts
		result, err := tx.Exec(ctx, `WITH due AS MATERIALIZED (
			SELECT id FROM auth.sessions
			WHERE LEAST(revoked_at,expires_at,absolute_expires_at)
				<= statement_timestamp()-$1::double precision*interval '24 hours'
			ORDER BY LEAST(revoked_at,expires_at,absolute_expires_at),id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM auth.sessions s USING due WHERE s.id=due.id`, cfg.SessionDays, batch)
		if err != nil {
			return err
		}
		removed += result.RowsAffected()
		for _, table := range []string{
			"email_verification_audit", "password_audit", "account_status_audit",
			"account_deletion_audit", "email_change_audit", "invitation_audit",
			"identity_audit",
			"access_audit",
			"auth_settings_audit",
			"smtp_settings_audit",
			"email_login_audit",
			"mfa_audit",
		} {
			// Identifiers come only from this fixed list, never from configuration/input.
			name := pgx.Identifier{"auth", table}.Sanitize()
			result, err := tx.Exec(ctx, `WITH due AS MATERIALIZED (
				SELECT id FROM `+name+`
				WHERE created_at <= statement_timestamp()-$1::double precision*interval '24 hours'
				ORDER BY created_at,id LIMIT $2 FOR UPDATE SKIP LOCKED
			)
			DELETE FROM `+name+` a USING due WHERE a.id=due.id`, cfg.SecurityAuditDays, batch)
			if err != nil {
				return err
			}
			removed += result.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	challenges, err := r.purgeTransientAuthData(ctx, batch)
	return removed + challenges, err
}
