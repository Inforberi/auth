package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func registrationError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_emails_email_key" {
		return passworddomain.ErrEmailAlreadyExists
	}
	return fmt.Errorf("insert user email: %w", err)
}
