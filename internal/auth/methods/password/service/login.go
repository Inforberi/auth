package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type LoginResult struct {
	UserID    accountdomain.UserID
	Token     string
	ExpiresAt time.Time
}

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
		if errors.Is(err, sessiondomain.ErrSessionNotFound) || errors.Is(err, sessiondomain.ErrSessionExpired) {
			return nil, passworddomain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &LoginResult{
		UserID:    authData.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
