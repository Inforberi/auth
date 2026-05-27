package register_service

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	register_domain "github.com/Inforberi/financial-intelligence/internal/featers/register/domain"
)

type RegisterResult struct {
	UserID    domain.UserID
	Token     string
	ExpiresAt time.Time
}

func (r *registerService) RegisterByEmail(
	ctx context.Context,
	email,
	password,
	userAgent,
	IP string,
) (*register_domain.RegisterResult, error) {
	// check email
	emailValue, err := domain.NewEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email in register email %w", err)
	}

	// validate password
	err = domain.ValidatePassword(password)
	if err != nil {
		return nil, fmt.Errorf("error validate password %w", err)
	}

	// check exist
	found, err := r.repo.ExistsByEmail(ctx, emailValue.String())
	if err != nil {
		return nil, fmt.Errorf("check email exists %w", err)
	}
	if found {
		return nil, ErrEmailAlreadyExists
	}

	// hash password
	hash, err := r.hasher.GenerateHash([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("err generate hash %w", err)
	}

	// create user
	userID, err := r.repo.CreateUser(ctx, emailValue.String(), hash)
	if err != nil {
		return nil, fmt.Errorf("register by email create user %w", err)
	}

	// create session
	session, err := r.session.CreateSession(ctx, userID, userAgent, IP)
	if err != nil {
		return nil, fmt.Errorf("register by email create session %w", err)
	}

	return &register_domain.RegisterResult{
		UserID:    userID,
		Token:     session.RawToken,
		ExpiresAt: session.ExpiredAt,
	}, nil
}
