package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

// Authenticate returns a server-only primary proof, not a session or completed MFA login.
// Its credential reference must be rechecked in the final issuance transaction.
func (l *PasswordService) Authenticate(ctx context.Context, input LoginInput) (mfaservice.PrimaryProof, error) {
	return l.authenticate(ctx, input, false)
}

func (l *PasswordService) authenticate(ctx context.Context, input LoginInput, administrative bool) (mfaservice.PrimaryProof, error) {
	var proof mfaservice.PrimaryProof
	email, err := parseCredentials(input.Email, input.Password)
	if err != nil {
		return proof, fmt.Errorf("service login: %w", err)
	}
	if len(input.Password) > 1024 {
		return proof, domain.ErrInvalidEmailOrPassword
	}
	if err := l.admitLogin(ctx, email.String(), input.IP, administrative); err != nil {
		return proof, err
	}
	authData, err := l.repo.FindByEmail(ctx, email.String())
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return proof, domain.ErrInvalidEmailOrPassword
		}
		return proof, fmt.Errorf("FindByEmail: %w", err)
	}
	if err := l.hash.Compare(ctx, input.Password, authData.PasswordHash); err != nil {
		if errors.Is(err, domain.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return proof, err
		}
		return proof, domain.ErrInvalidEmailOrPassword
	}
	if err := l.rehash(ctx, authData, input.Password); err != nil {
		return proof, err
	}
	return mfaservice.PrimaryProof{Administrative: administrative, UserID: authData.UserID, AuthVersion: authData.AuthVersion, Method: "password", Reference: authData.PasswordHash, VerifiedAt: time.Now().UTC()}, nil
}
