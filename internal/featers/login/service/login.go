package login_service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
)

func (l *LoginService) Login(ctx context.Context, input login_domain.LoginInput) (*login_domain.LoginResult, error) {
	// normalize email
	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}

	// check email in db
	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, login_domain.ErrNotFound) {
			return nil, login_domain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("FindByEmail: %w", err)
	}

	// compare password
	if err := l.hash.Compare(input.Password, authData.PasswordHash); err != nil {
		return nil, login_domain.ErrInvalidEmailOrPassword
	}

	// create session
	session, err := l.session.CreateSession(ctx, authData.UserID, input.UserAgent, input.IP)
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &login_domain.LoginResult{
		UserID:    authData.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiredAt,
	}, nil
}
