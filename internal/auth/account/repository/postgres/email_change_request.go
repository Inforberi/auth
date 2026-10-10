package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) EmailChangeSnapshot(ctx context.Context, user domain.UserID) (domain.EmailChangeSnapshot, error) {
	var snapshot domain.EmailChangeSnapshot
	err := r.db.QueryRow(ctx, `SELECT u.id,e.id,e.email,p.password_hash,u.auth_version
		FROM auth.users u JOIN auth.password_credentials p ON p.user_id=u.id
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=u.id
		WHERE u.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND e.verified_at IS NOT NULL`, user).
		Scan(&snapshot.UserID, &snapshot.EmailID, &snapshot.Email, &snapshot.PasswordHash, &snapshot.AuthVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, domain.ErrFreshAuthRequired
	}
	return snapshot, err
}

func (r *Repository) RequestEmailChange(ctx context.Context, snapshot domain.EmailChangeSnapshot, session, email string, intent domain.EmailChangeIntent) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		version, err := lockChangeAccount(ctx, tx, snapshot.UserID)
		if err != nil {
			return err
		}
		if version != snapshot.AuthVersion {
			return domain.ErrFreshAuthRequired
		}
		if err := requireChangeSession(ctx, tx, snapshot.UserID, session, version); err != nil {
			return err
		}
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p JOIN auth.user_emails e
			ON e.id=p.email_id AND e.user_id=p.user_id WHERE p.user_id=$1 AND p.password_hash=$2
			AND e.id=$3 AND e.email=$4 AND e.verified_at IS NOT NULL)`, snapshot.UserID, snapshot.PasswordHash, snapshot.EmailID, snapshot.Email).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return domain.ErrFreshAuthRequired
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.email_changes SET state='expired' WHERE user_id=$1 AND state='pending' AND expires_at<=clock_timestamp()`, snapshot.UserID); err != nil {
			return err
		}
		var pending, occupied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.email_changes WHERE user_id=$1 AND state='pending'),
			EXISTS(SELECT 1 FROM auth.user_emails WHERE email=$2)`, snapshot.UserID, email).Scan(&pending, &occupied); err != nil {
			return err
		}
		if pending {
			return domain.ErrEmailChangePending
		}
		if occupied {
			return domain.ErrInvalidEmailChange
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO auth.email_changes(user_id,email_id,old_email,new_email,auth_version,session_hash,
			confirm_digest,report_digest,completion_payload,expires_at,protect_until)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, snapshot.UserID, snapshot.EmailID, snapshot.Email, email,
			version, session, intent.ConfirmDigest, intent.ReportDigest, intent.CompletionPayload, intent.ExpiresAt, intent.ProtectUntil).Scan(&id); err != nil {
			return err
		}
		if err := queueChangeMail(ctx, tx, id, "confirm", intent.ConfirmPayload, intent.ExpiresAt); err != nil {
			return err
		}
		if err := queueChangeMail(ctx, tx, id, "notice", intent.NoticePayload, intent.ProtectUntil); err != nil {
			return err
		}
		return auditEmailChange(ctx, tx, snapshot.UserID, id, "requested")
	})
}
