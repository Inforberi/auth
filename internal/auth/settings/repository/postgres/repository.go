package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type Repository struct {
	db                *pgxpool.Pool
	available         domain.PublicMethods
	runtimeConfigured bool
	tokens            domain.TokenIssuance
}

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewWithRuntime(db *pgxpool.Pool, available domain.PublicMethods, tokens domain.TokenIssuance) *Repository {
	return &Repository{db: db, available: available, tokens: tokens, runtimeConfigured: true}
}

const policyColumns = `version,password_enabled,email_otp_enabled,google_enabled,telegram_enabled,
	registration_enabled,google_registration_enabled,telegram_registration_enabled,password_email_verification,
	token_session_exchange_enabled,token_native_enabled`

func scanSnapshot(row pgx.Row) (domain.Snapshot, error) {
	var s domain.Snapshot
	err := row.Scan(&s.Version, &s.Policy.Methods.Password, &s.Policy.Methods.EmailOTP, &s.Policy.Methods.Google, &s.Policy.Methods.Telegram,
		&s.Policy.Registration.Enabled, &s.Policy.Registration.Google, &s.Policy.Registration.Telegram, &s.Policy.PasswordEmailVerification,
		&s.Policy.TokenIssuance.SessionExchange, &s.Policy.TokenIssuance.Native)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Snapshot{}, domain.ErrNotInitialized
	}
	return s, err
}

func policyValues(p domain.Policy) []any {
	return []any{p.Methods.Password, p.Methods.EmailOTP, p.Methods.Google, p.Methods.Telegram, p.Registration.Enabled, p.Registration.Google, p.Registration.Telegram, string(p.PasswordEmailVerification), p.TokenIssuance.SessionExchange, p.TokenIssuance.Native}
}

func (r *Repository) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit closes the transaction.
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
