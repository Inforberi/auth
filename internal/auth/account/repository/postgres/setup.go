package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) CheckSetupOpen(ctx context.Context) error {
	var closed bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.initial_setup WHERE initialized_at IS NOT NULL)
		OR EXISTS(SELECT 1 FROM auth.roles WHERE key='super_admin' AND system)`).Scan(&closed)
	if err != nil {
		return err
	}
	if closed {
		return domain.ErrSetupClosed
	}
	return nil
}

// Access lock precedes the singleton row; the marker is independent of user/role survival.
func lockSetup(ctx context.Context, tx pgx.Tx) error {
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.initial_setup(singleton) VALUES(true) ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	var closed bool
	if err := tx.QueryRow(ctx, `SELECT initialized_at IS NOT NULL FROM auth.initial_setup WHERE singleton FOR UPDATE`).Scan(&closed); err != nil {
		return err
	}
	if closed {
		return domain.ErrSetupClosed
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.roles WHERE key='super_admin' AND system)`).Scan(&closed); err != nil {
		return err
	}
	if closed {
		return domain.ErrSetupClosed
	}
	return nil
}

func (r *Repository) SaveSetup(ctx context.Context, operator, request string, payload []byte) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockSetup(ctx, tx); err != nil {
			return err
		}
		// Pin the operator proof across instances. Reissues never change the installation operator.
		err := tx.QueryRow(ctx, `UPDATE auth.initial_setup SET operator_hash=$1,request_hash=$2,payload=$3,
			created_at=statement_timestamp(),expires_at=statement_timestamp()+interval '10 minutes',attempts=0
			WHERE singleton AND (operator_hash IS NULL OR operator_hash=$1)
			AND (created_at IS NULL OR created_at<=clock_timestamp()-interval '1 minute') RETURNING expires_at`, operator, request, payload).Scan(&expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrSetupConflict
		}
		return err
	})
	return expires, err
}

func (r *Repository) CompleteSetup(ctx context.Context, operator, request string, check service.SetupCheck) error {
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var err error
		_, rejected, err = CompleteSetupInTransaction(ctx, tx, operator, request, check)
		return err
	})
	if err != nil {
		return err
	}
	if rejected {
		return domain.ErrSetupInvalid
	}
	return nil
}

// CompleteSetupInTransaction lets platform bootstrap persist its authority atomically
// with the Auth administrator. A rejected proof must be committed to count the attempt;
// every non-nil error requires rollback. The caller owns the transaction.
func CompleteSetupInTransaction(ctx context.Context, tx pgx.Tx, operator, request string, check service.SetupCheck) (*domain.SetupAccount, bool, error) {
	if err := lockSetup(ctx, tx); err != nil {
		return nil, false, err
	}
	var payload []byte
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT payload,clock_timestamp() FROM auth.initial_setup WHERE singleton
		AND operator_hash=$1 AND request_hash=$2 AND expires_at>clock_timestamp() AND attempts<5`, operator, request).Scan(&payload, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, domain.ErrSetupInvalid
	}
	if err != nil {
		return nil, false, err
	}
	account, err := check(payload, now)
	if errors.Is(err, domain.ErrSetupInvalid) {
		_, err := tx.Exec(ctx, `UPDATE auth.initial_setup SET attempts=attempts+1 WHERE singleton`)
		return nil, true, err
	}
	if err != nil {
		return nil, false, err
	}
	if account == nil {
		return nil, false, domain.ErrDependencyUnavailable
	}
	return account, false, commitInitialAdministrator(ctx, tx, account)
}
