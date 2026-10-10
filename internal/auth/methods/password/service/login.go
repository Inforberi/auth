package service

import (
	"context"
	"errors"
	"fmt"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (l *PasswordService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	email, err := parseCredentials(input.Email, input.Password)
	if err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}

	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, passworddomain.ErrUserNotFound) {
			return nil, passworddomain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("FindByEmail: %w", err)
	}

	if err := l.hash.Compare(input.Password, authData.PasswordHash); err != nil {
		return nil, passworddomain.ErrInvalidEmailOrPassword
	}

	session, err := l.session.CreateSessionAtVersion(ctx, authData.UserID, input.UserAgent, input.IP, authData.AuthVersion)
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &LoginResult{
		UserID:    authData.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
