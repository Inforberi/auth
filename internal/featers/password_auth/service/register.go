package password_service

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

func (r *PasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	IP string,
) (*password_domain.RegisterResult, error) {
	emailValue, err := domain.NewEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email in register email %w", err)
	}

	err = domain.ValidatePassword(password)
	if err != nil {
		return nil, fmt.Errorf("error validate password %w", err)
	}

	found, err := r.repo.ExistsByEmail(ctx, emailValue.String())
	if err != nil {
		return nil, fmt.Errorf("check email exists %w", err)
	}
	if found {
		return nil, ErrEmailAlreadyExists
	}

	hash, err := r.hash.GenerateHash([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("err generate hash %w", err)
	}

	userID, err := r.repo.CreateUser(ctx, emailValue.String(), hash)
	if err != nil {
		return nil, fmt.Errorf("register by email create user %w", err)
	}

	session, err := r.session.CreateSession(ctx, userID, userAgent, IP)
	if err != nil {
		return nil, fmt.Errorf("register by email create session %w", err)
	}

	return &password_domain.RegisterResult{
		UserID:    userID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
