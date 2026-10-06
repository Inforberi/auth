package service

import (
	"context"
	"errors"
	"fmt"

	emailmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/email/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func (l *PasswordService) Login(ctx context.Context, input passwordmodel.LoginInput) (*passwordmodel.LoginResult, error) {
	// normalize email
	email, err := emailmodel.NewEmail(input.Email)
	if err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}

	// check email in db
	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, passwordmodel.ErrUserNotFound) {
			return nil, passwordmodel.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("FindByEmail: %w", err)
	}

	// compare password
	if err := l.hash.Compare(input.Password, authData.PasswordHash); err != nil {
		return nil, passwordmodel.ErrInvalidEmailOrPassword
	}

	// create session
	session, err := l.session.CreateSession(ctx, authData.UserID, input.UserAgent, input.IP)
	if err != nil {
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &passwordmodel.LoginResult{
		UserID:    authData.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
