package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type RegisterResult struct {
	VerificationRequired bool
	UserID               accountdomain.UserID
	Token                string
	ExpiresAt            time.Time
}

func (r *PasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	ip string,
) (*RegisterResult, error) {
	emailValue, err := parseCredentials(email, password)
	if err != nil {
		return nil, fmt.Errorf("register credentials: %w", err)
	}

	err = passworddomain.ValidatePassword(password)
	if err != nil {
		return nil, fmt.Errorf("error validate password %w", err)
	}

	if r.checkPolicy != nil {
		if err := r.checkPolicy(ctx, true); err != nil {
			return nil, err
		}
	}
	found, err := r.repo.ExistsByEmail(ctx, emailValue.String())
	if err != nil {
		return nil, fmt.Errorf("check email exists %w", err)
	}
	if found {
		return nil, passworddomain.ErrEmailAlreadyExists
	}

	hash, err := r.hash.GenerateHash(ctx, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("err generate hash %w", err)
	}

	userID, err := r.repo.CreateUser(ctx, emailValue.String(), hash)
	if err != nil {
		return nil, fmt.Errorf("register by email create user %w", err)
	}

	session, err := r.session.CreateSessionAtVersion(ctx, userID, userAgent, ip, 1)
	if errors.Is(err, accountdomain.ErrEmailUnverified) {
		return &RegisterResult{UserID: userID, VerificationRequired: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("register by email create session %w", err)
	}

	return &RegisterResult{
		UserID:    userID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
