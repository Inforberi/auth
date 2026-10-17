package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
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
	Challenge *mfaservice.LoginChallenge
}

func (l *PasswordService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	return l.login(ctx, input, false)
}

func (l *PasswordService) LoginAdministrator(ctx context.Context, input LoginInput) (*LoginResult, error) {
	return l.login(ctx, input, true)
}

func (l *PasswordService) login(ctx context.Context, input LoginInput, administrative bool) (*LoginResult, error) {
	proof, err := l.authenticate(ctx, input, administrative)
	if err != nil {
		return nil, err
	}
	session, err := l.session.BeginLogin(ctx, proof, input.UserAgent, input.IP)
	if err != nil {
		if administrative && (errors.Is(err, mfadomain.ErrProofRequired) || errors.Is(err, mfadomain.ErrConflict) || errors.Is(err, sessiondomain.ErrMFARequired)) {
			return nil, passworddomain.ErrInvalidEmailOrPassword
		}
		if errors.Is(err, sessiondomain.ErrSessionNotFound) || errors.Is(err, sessiondomain.ErrSessionExpired) {
			return nil, passworddomain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("CreateSession: %w", err)
	}

	return &LoginResult{
		UserID:    proof.UserID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
		Challenge: session.Challenge,
	}, nil
}
