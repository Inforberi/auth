package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) CanRequestEmailBinding(ctx context.Context, actor accessservice.Principal) error {
	allowed, err := accesspostgres.New(r.db).HasPermission(ctx, actor, accesssettings.EmailBindingManage)
	if err != nil {
		return err
	}
	if !allowed {
		return accessdomain.ErrForbidden
	}
	return nil
}

func requireInitialEmailTarget(ctx context.Context, tx pgx.Tx, user domain.UserID) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users u WHERE id=$1 AND status='active' AND deleted_at IS NULL
		AND EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.user_emails WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL)`, user).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrEmailBindingConflict
	}
	return version, err
}

func (r *Repository) IssueEmailBinding(ctx context.Context, c service.EmailBindingCommand) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := accesspostgres.AuthorizeMutation(ctx, tx, c.Actor, string(c.UserID), accesssettings.EmailBindingManage)
		if err != nil {
			return err
		}
		if c.Actor.UserID == c.UserID {
			return domain.ErrEmailBindingConflict
		}
		version, err := requireInitialEmailTarget(ctx, tx, c.UserID)
		if err != nil {
			return err
		}
		var occupied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_emails WHERE email=$1)`, c.Email).Scan(&occupied); err != nil {
			return err
		}
		if occupied {
			return domain.ErrEmailBindingConflict
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.email_bindings(user_id,actor_id,actor_session_hash,auth_version,email,verifier,payload,expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,LEAST($8::timestamptz,statement_timestamp()+$9::double precision*interval '1 second'))
			ON CONFLICT(user_id) DO UPDATE SET id=gen_random_uuid(),actor_id=EXCLUDED.actor_id,
			actor_session_hash=EXCLUDED.actor_session_hash,auth_version=EXCLUDED.auth_version,email=EXCLUDED.email,
			verifier=EXCLUDED.verifier,payload=EXCLUDED.payload,attempts=0,created_at=statement_timestamp(),expires_at=EXCLUDED.expires_at,
			available_at=statement_timestamp(),delivery_attempts=0,lease=NULL,lease_until=NULL,delivered_at=NULL RETURNING expires_at`,
			c.UserID, c.Actor.UserID, c.Actor.TokenHash, version, c.Email, c.Verifier, c.Payload, deadline, c.TTL.Seconds()).Scan(&expires)
		if err != nil {
			return err
		}
		return auditEmailBinding(ctx, tx, c.UserID, c.Actor.UserID, version, "email_binding_issued")
	})
	return expires, err
}

func auditEmailBinding(ctx context.Context, tx pgx.Tx, user, actor domain.UserID, version domain.AuthVersion, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth.email_verification_audit(user_id,actor_id,auth_version,event) VALUES ($1,$2,$3,$4)`, user, actor, version, event)
	return err
}
