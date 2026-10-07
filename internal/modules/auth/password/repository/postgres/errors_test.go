package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestRegistrationError(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505", ConstraintName: "user_emails_email_key"}
	if !errors.Is(registrationError(fmt.Errorf("wrapped: %w", duplicate)), passwordmodel.ErrEmailAlreadyExists) {
		t.Fatal("email conflict not mapped")
	}
	for _, err := range []error{errors.New("connection failed"), &pgconn.PgError{Code: "23505", ConstraintName: "users_pkey"}, &pgconn.PgError{Code: "23514", ConstraintName: "user_emails_email_key"}} {
		got := registrationError(err)
		if errors.Is(got, passwordmodel.ErrEmailAlreadyExists) || !errors.Is(got, err) {
			t.Fatal("unrelated database error hidden")
		}
	}
}
