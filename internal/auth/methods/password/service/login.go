package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
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
	email, err := parseCredentials(input.Email, input.Password)
	if err != nil {
		return nil, fmt.Errorf("service login: %w", err)
	}
	if len(input.Password) > 1024 {
		return nil, passworddomain.ErrInvalidEmailOrPassword
	}
	if l.loginLimit == nil {
		return nil, passworddomain.ErrLoginUnavailable
	}
	if err := l.loginLimit.Allow(ctx, email.String(), input.IP); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, passworddomain.ErrUserNotFound) {
			return nil, passworddomain.ErrInvalidEmailOrPassword
		}
		return nil, fmt.Errorf("FindByEmail: %w", err)
	}

	if err := l.hash.Compare(ctx, input.Password, authData.PasswordHash); err != nil {
		if errors.Is(err, passworddomain.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, passworddomain.ErrInvalidEmailOrPassword
	}

	if err := l.rehash(ctx, authData, input.Password); err != nil {
		return nil, err
	}
	session, err := l.session.BeginLogin(ctx, mfaservice.PrimaryProof{
		UserID:      authData.UserID,
		AuthVersion: authData.AuthVersion, Method: "password", Reference: authData.PasswordHash, VerifiedAt: time.Now().UTC(),
	}, input.UserAgent, input.IP)
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
		Challenge: session.Challenge,
	}, nil
}
