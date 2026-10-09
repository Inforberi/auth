package postgres

import (
	"context"
	"errors"
	"fmt"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	sql := `
	SELECT EXISTS(
		SELECT 1
		FROM auth.user_emails
		WHERE email = $1
	)
	`

	var exists bool

	err := r.db.QueryRow(ctx, sql, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query ExistByEmail: %w", err)
	}

	return exists, nil
}

func (l *PasswordRepo) FindByEmail(ctx context.Context, email string) (*passworddomain.Credential, error) {
	sql := `
	SELECT pc.user_id, pc.password_hash, u.auth_version
	FROM auth.password_credentials pc
	JOIN auth.user_emails e ON e.id = pc.email_id AND e.user_id = pc.user_id
	JOIN auth.users u ON u.id=pc.user_id
	WHERE e.email = $1 AND u.status='active' AND u.deleted_at IS NULL
	`
	var userID accountdomain.UserID
	var passwordHash string
	var version int64

	err := l.db.QueryRow(ctx, sql, email).Scan(&userID, &passwordHash, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("FindByEmail: %w", passworddomain.ErrUserNotFound)
		}
		return nil, fmt.Errorf("repo find by email %w", err)
	}

	return &passworddomain.Credential{
		AuthVersion:  version,
		UserID:       userID,
		PasswordHash: passwordHash,
	}, nil
}

func (p *PasswordRepo) FindUserByUserID(ctx context.Context, userID accountdomain.UserID) (*passworddomain.Credential, error) {
	sql := `
	SELECT password_hash
	FROM auth.password_credentials
	WHERE user_id = $1
	`
	var passwordHash string
	err := p.db.QueryRow(ctx, sql, userID).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passworddomain.ErrNotFound
		}
		return nil, fmt.Errorf("err find user %w", err)
	}

	return &passworddomain.Credential{
		PasswordHash: passwordHash,
	}, nil
}

type PasswordRepo struct {
	db           *pgxpool.Pool
	registration func(context.Context, pgx.Tx, accountdomain.UserID, accountdomain.AddressID, string) error
}

func NewWithRegistration(db *pgxpool.Pool, queue func(context.Context, pgx.Tx, accountdomain.UserID, accountdomain.AddressID, string) error) *PasswordRepo {
	return &PasswordRepo{db: db, registration: queue}
}

func New(db *pgxpool.Pool) *PasswordRepo {
	return &PasswordRepo{db: db}
}

func (p *PasswordRepo) UpdatePasswordHash(ctx context.Context, userID accountdomain.UserID, passwordHash string) error {
	return p.recoveryTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var id accountdomain.UserID
		if err := tx.QueryRow(ctx, "SELECT id FROM auth.users WHERE id=$1 FOR UPDATE", userID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return passworddomain.ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1", userID, passwordHash); err != nil {
			return err
		}
		return revokeForPassword(ctx, tx, userID, "password_changed")
	})
}
