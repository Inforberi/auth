package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

const currentRecoveryOperator = `EXISTS(SELECT 1 FROM pg_catalog.pg_roles p
	WHERE p.oid=r.operator_oid AND p.rolname=r.operator_name AND p.rolcanlogin
	AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname='auth_mfa_recovery_operator'
	AND pg_catalog.pg_has_role(p.oid,g.oid,'MEMBER')))`

func (r *Repository) FindRecoveryOwner(ctx context.Context, request, digest, binding string) (accountdomain.UserID, error) {
	var user accountdomain.UserID
	err := r.db.QueryRow(ctx, `SELECT r.user_id FROM auth.mfa_recovery_requests r
		JOIN auth.mfa_login_challenges c ON c.digest=r.challenge_digest AND c.user_id=r.user_id
		JOIN auth.users u ON u.id=r.user_id WHERE r.request_id=$1 AND c.digest=$2 AND c.binding_hash=$3
		AND r.auth_version=u.auth_version AND c.auth_version=u.auth_version AND c.attempts<5
		AND c.expires_at>clock_timestamp() AND r.expires_at>clock_timestamp() AND r.attempts<5
		AND r.state='approved' AND u.status='active' AND u.deleted_at IS NULL AND `+currentRecoveryOperator,
		request, digest, binding).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrInvalidCode
	}
	return user, err
}

type recoveryIntent struct {
	secret       []byte
	now, created time.Time
}

func (r *Repository) CompleteRecovery(ctx context.Context, input service.RecoveryCompletion) error {
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
		proof, err := lockLoginChallenge(ctx, tx, input.Digest, input.BindingHash, true)
		if err != nil {
			return err
		}
		if proof.EnrollmentRequired || proof.UserID != input.UserID || (!proof.Administrative && (input.AllowPrimary == nil || !input.AllowPrimary(proof.Method, proof.Issuer))) {
			return domain.ErrInvalidCode
		}
		if err := RequireLoginPrimary(ctx, tx, proof.PrimaryProof); err != nil {
			if errors.Is(err, domain.ErrProofRequired) {
				return domain.ErrInvalidCode
			}
			return err
		}
		var intent recoveryIntent
		err = tx.QueryRow(ctx, `SELECT r.secret,clock_timestamp(),r.created_at FROM auth.mfa_recovery_requests r
			WHERE r.user_id=$1 AND r.request_id=$2 AND r.auth_version=$3 AND r.challenge_digest=$4
			AND r.state='approved' AND r.attempts<5 AND r.expires_at>clock_timestamp()
			AND `+currentRecoveryOperator+` FOR UPDATE OF r`, proof.UserID, input.RequestID, proof.AuthVersion, input.Digest).
			Scan(&intent.secret, &intent.now, &intent.created)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCode
		}
		if err != nil {
			return err
		}
		step, err := input.Check(intent.secret, -1, intent.now)
		if errors.Is(err, domain.ErrInvalidCode) {
			rejected = true
			_, err := tx.Exec(ctx, `UPDATE auth.mfa_recovery_requests SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
			return err
		}
		if err != nil {
			return err
		}
		return commitRecoveredFactor(ctx, tx, proof.PrimaryProof, input, intent, step)
	})
	if err != nil {
		return err
	}
	if rejected {
		return domain.ErrInvalidCode
	}
	return nil
}

func commitRecoveredFactor(ctx context.Context, tx pgx.Tx, proof service.PrimaryProof, input service.RecoveryCompletion, intent recoveryIntent, step int64) error {
	changed, err := tx.Exec(ctx, `UPDATE auth.mfa_totp SET secret=$2,last_step=$3,enabled_at=clock_timestamp() WHERE user_id=$1`, proof.UserID, intent.secret, step)
	if err != nil {
		return err
	}
	if changed.RowsAffected() != 1 {
		return domain.ErrInvalidCode
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1`, proof.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) SELECT $1,unnest($2::text[])`, proof.UserID, input.RecoveryDigests); err != nil {
		return err
	}
	queued, err := queueRecoveryNotice(ctx, tx, proof.UserID, input, intent)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.mfa_audit(user_id,event,request_id,auth_version,operator_oid,operator_name,environment,reason,notification_queued)
		SELECT user_id,'recovery_completed',request_id,auth_version+1,operator_oid,operator_name,environment,reason,$2
		FROM auth.mfa_recovery_requests WHERE user_id=$1`, proof.UserID, queued)
	if err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM auth.password_resets WHERE user_id=$1`,
		`DELETE FROM auth.email_login_challenges WHERE user_id=$1`,
		`DELETE FROM auth.email_bindings WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, proof.UserID); err != nil {
			return err
		}
	}
	return invalidateFactors(ctx, tx, proof.UserID)
}

func queueRecoveryNotice(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, input service.RecoveryCompletion, intent recoveryIntent) (bool, error) {
	var email string
	err := tx.QueryRow(ctx, `SELECT email::text FROM auth.user_emails WHERE user_id=$1 AND verified_at<=$2
		ORDER BY verified_at,id LIMIT 1 FOR UPDATE`, user, intent.created).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	payload, err := input.PrepareNotice(email, intent.now)
	if err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_outbox(user_id,request_id,payload) VALUES($1,$2,$3)`, user, input.RequestID, payload)
	return err == nil, err
}
