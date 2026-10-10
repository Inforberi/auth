package postgres

import (
	"context"
	"errors"
	"fmt"

	pgx "github.com/jackc/pgx/v5"

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

func (r *PasswordRepo) FindByEmail(ctx context.Context, email string) (*passworddomain.Credential, error) {
	sql := `
	SELECT pc.user_id, pc.password_hash, u.auth_version
	FROM auth.password_credentials pc
	JOIN auth.user_emails e ON e.id = pc.email_id AND e.user_id = pc.user_id
	JOIN auth.users u ON u.id = pc.user_id
	WHERE e.email = $1
	  AND u.status = 'active'
	  AND u.deleted_at IS NULL
	`
	var userID accountdomain.UserID
	var passwordHash string
	var version int64

	err := r.db.QueryRow(ctx, sql, email).Scan(&userID, &passwordHash, &version)
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

func (r *PasswordRepo) FindUserByUserID(ctx context.Context, userID accountdomain.UserID) (*passworddomain.Credential, error) {
	sql := `
	SELECT p.password_hash
	FROM auth.password_credentials p JOIN auth.users u ON u.id=p.user_id
	WHERE p.user_id = $1 AND u.status='active' AND u.deleted_at IS NULL
	`
	var passwordHash string
	err := r.db.QueryRow(ctx, sql, userID).Scan(&passwordHash)
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
