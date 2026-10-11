package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ResolveIdentityAccount(ctx context.Context, key domain.IdentityKey, allowRegistration bool) (*domain.User, error) {
	user, err := r.findIdentityAccount(ctx, key)
	if !errors.Is(err, domain.ErrIdentityNotFound) || !allowRegistration {
		return user, err
	}
	user = &domain.User{}
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO auth.users DEFAULT VALUES
			RETURNING id,status,auth_version,created_at,updated_at,deleted_at`).Scan(
			&user.ID, &user.Status, &user.AuthVersion, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.linked_identities(issuer,subject,user_id)
			VALUES ($1,$2,$3)`, key.Issuer, key.Subject, user.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO auth.user_profile(user_id) VALUES ($1)`, user.ID)
		return err
	})
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && conflict.Code == "23505" && conflict.ConstraintName == "linked_identities_key" {
		// The losing transaction is rolled back, including its candidate user.
		// Read the committed owner; never overwrite or reassign an existing identity.
		return r.findIdentityAccount(ctx, key)
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Repository) findIdentityAccount(ctx context.Context, key domain.IdentityKey) (*domain.User, error) {
	user := &domain.User{}
	err := r.db.QueryRow(ctx, `SELECT u.id,u.status,u.auth_version,u.created_at,u.updated_at,u.deleted_at
		FROM auth.linked_identities i JOIN auth.users u ON u.id=i.user_id
		WHERE i.issuer=$1 AND i.subject=$2`, key.Issuer, key.Subject).Scan(
		&user.ID, &user.Status, &user.AuthVersion, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}
