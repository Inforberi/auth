package password_service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

func (l *PasswordService) Login(ctx context.Context, input password_domain.LoginInput) (*password_domain.LoginResult, error) {
	// normalize email
	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}

	// check email in db
	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, password_domain.ErrNotFound) {
			return nil, password_domain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("FindByEmail: %w", err)
	}

	// compare password
	if err := l.hash.Compare(input.Password, authData.PasswordHash); err != nil {
		return nil, password_domain.ErrInvalidEmailOrPassword
	}

	// create session
	session, err := l.session.CreateSession(ctx, authData.UserID, input.UserAgent, input.IP)
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &password_domain.LoginResult{
		UserID:    authData.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
