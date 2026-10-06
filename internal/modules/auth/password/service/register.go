package service

import (
	"context"
	"fmt"

	emailmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/email/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func (r *PasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	ip string,
) (*passwordmodel.RegisterResult, error) {
	emailValue, err := emailmodel.NewEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email in register email %w", err)
	}

	err = passwordmodel.ValidatePassword(password)
	if err != nil {
		return nil, fmt.Errorf("error validate password %w", err)
	}

	found, err := r.repo.ExistsByEmail(ctx, emailValue.String())
	if err != nil {
		return nil, fmt.Errorf("check email exists %w", err)
	}
	if found {
		return nil, passwordmodel.ErrEmailAlreadyExists
	}

	hash, err := r.hash.GenerateHash([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("err generate hash %w", err)
	}

	userID, err := r.repo.CreateUser(ctx, emailValue.String(), hash)
	if err != nil {
		return nil, fmt.Errorf("register by email create user %w", err)
	}

	session, err := r.session.CreateSession(ctx, userID, userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("register by email create session %w", err)
	}

	return &passwordmodel.RegisterResult{
		UserID:    userID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiresAt,
	}, nil
}
