package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func (r *TemporaryPasswordRepo) FindTemporaryProvision(ctx context.Context, command accountservice.ProvisionCommand) (*service.TemporaryIssueResult, error) {
	var result *service.TemporaryIssueResult
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, command.Input.Actor, "", settings.UsersManage); err != nil {
			return err
		}
		var user accountdomain.UserID
		var fingerprint string
		err := tx.QueryRow(ctx, `SELECT user_id,fingerprint FROM auth.account_provisions WHERE actor_id=$1 AND request_key=$2`, command.Input.Actor.UserID, command.Input.IdempotencyKey).Scan(&user, &fingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if fingerprint != command.Fingerprint {
			return accountdomain.ErrProvisionConflict
		}
		result = &service.TemporaryIssueResult{UserID: user, Reused: true}
		return nil
	})
	return result, err
}

func (r *TemporaryPasswordRepo) FindTemporaryReissue(ctx context.Context, input service.TemporaryReissueInput) (*service.TemporaryIssueResult, error) {
	var result *service.TemporaryIssueResult
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := accesspostgres.AuthorizeMutation(ctx, tx, input.Actor, string(input.UserID), settings.UsersManage); err != nil {
			return err
		}
		var user accountdomain.UserID
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT user_id,expires_at FROM auth.temporary_password_reissues WHERE actor_id=$1 AND request_key=$2`, input.Actor.UserID, input.IdempotencyKey).Scan(&user, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if user != input.UserID {
			return accountdomain.ErrProvisionConflict
		}
		result = &service.TemporaryIssueResult{UserID: user, Reused: true, ExpiresAt: expires}
		return nil
	})
	return result, err
}
