package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func (r *TemporaryPasswordRepo) FindTemporaryProvision(ctx context.Context, command accountservice.ProvisionCommand) (*service.TemporaryIssueResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user *accountdomain.UserID
	var fingerprint *string
	err := r.db.QueryRow(ctx, `SELECT p.user_id,p.fingerprint FROM auth.users a
		LEFT JOIN auth.account_provisions p ON p.actor_id=a.id AND p.request_key=$2
		WHERE a.id=$1 AND a.status='active' AND a.deleted_at IS NULL`, command.Input.ActorID, command.Input.IdempotencyKey).Scan(&user, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, accountdomain.ErrProvisionConflict
	}
	if err != nil || user == nil {
		return nil, err
	}
	if fingerprint == nil || *fingerprint != command.Fingerprint {
		return nil, accountdomain.ErrProvisionConflict
	}
	return &service.TemporaryIssueResult{UserID: *user, Reused: true}, nil
}

func (r *TemporaryPasswordRepo) FindTemporaryReissue(ctx context.Context, input service.TemporaryReissueInput) (*service.TemporaryIssueResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user *accountdomain.UserID
	var expires *time.Time
	err := r.db.QueryRow(ctx, `SELECT p.user_id,p.expires_at FROM auth.users a
		LEFT JOIN auth.temporary_password_reissues p ON p.actor_id=a.id AND p.request_key=$2
		WHERE a.id=$1 AND a.status='active' AND a.deleted_at IS NULL`, input.ActorID, input.IdempotencyKey).Scan(&user, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, accountdomain.ErrProvisionConflict
	}
	if err != nil || user == nil {
		return nil, err
	}
	if *user != input.UserID {
		return nil, accountdomain.ErrProvisionConflict
	}
	return &service.TemporaryIssueResult{UserID: *user, Reused: true, ExpiresAt: *expires}, nil
}
