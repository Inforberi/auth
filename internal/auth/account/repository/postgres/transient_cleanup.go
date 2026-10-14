package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func (r *Repository) purgeTransientAuthData(ctx context.Context, batch int) (int64, error) {
	var removed int64
	// Expiry discards only the pending encrypted intent, never the installation marker or operator pin.
	if _, err := r.db.Exec(ctx, `UPDATE auth.initial_setup SET request_hash=NULL,payload=NULL,created_at=NULL,expires_at=NULL,attempts=0
		WHERE singleton AND initialized_at IS NULL AND expires_at<=statement_timestamp()`); err != nil {
		return 0, err
	}
	for _, challenge := range []struct{ table, key, expiry string }{
		{"email_verifications", "digest", "expires_at"},
		{"email_bindings", "user_id", "expires_at"},
		{"mfa_enrollments", "user_id", "expires_at"},
		{"mfa_recovery_requests", "user_id", "expires_at"},
		{"mfa_login_challenges", "user_id", "expires_at"},
		{"password_resets", "digest", "expires_at"},
		{"email_login_challenges", "digest", "expires_at"},
		{"temporary_password_tokens", "digest", "expires_at"},
		{"temporary_password_credentials", "user_id", "expires_at"},
		{"account_invitations", "digest", "expires_at"},
		{"email_changes", "id", "GREATEST(protect_until,recovery_expires_at)"},
	} {
		if challenge.table == "account_invitations" && !r.invitationDelivery {
			continue
		}
		if challenge.table == "email_changes" && !r.emailChangeDelivery {
			continue
		}
		name := pgx.Identifier{"auth", challenge.table}.Sanitize()
		key := pgx.Identifier{challenge.key}.Sanitize()
		result, err := r.db.Exec(ctx, `WITH due AS (
			SELECT `+key+` FROM `+name+` WHERE `+challenge.expiry+`<=statement_timestamp()
			ORDER BY `+challenge.expiry+`,`+key+` LIMIT $1 FOR UPDATE SKIP LOCKED
		) DELETE FROM `+name+` t USING due WHERE t.`+key+`=due.`+key, batch)
		if err != nil {
			return removed, err
		}
		removed += result.RowsAffected()
	}
	for _, table := range []string{"email_verification_outbox", "password_reset_outbox", "email_login_outbox", "email_change_outbox", "invitation_outbox"} {
		if table == "invitation_outbox" && !r.invitationDelivery {
			continue
		}
		if table == "email_change_outbox" && !r.emailChangeDelivery {
			continue
		}
		name := pgx.Identifier{"auth", table}.Sanitize()
		for _, due := range []struct{ predicate, order string }{
			{"expires_at<=statement_timestamp()", "expires_at,id"},
			{"attempts>=5 AND (lease_until IS NULL OR lease_until<=statement_timestamp())", "lease_until NULLS FIRST,id"},
		} {
			result, err := r.db.Exec(ctx, `WITH due AS (
				SELECT id FROM `+name+` WHERE `+due.predicate+`
				ORDER BY `+due.order+` LIMIT $1 FOR UPDATE SKIP LOCKED
			) DELETE FROM `+name+` t USING due WHERE t.id=due.id`, batch)
			if err != nil {
				return removed, err
			}
			removed += result.RowsAffected()
		}
	}
	return removed, nil
}
