package service

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type reauthenticationRepository interface {
	FindUserByUserID(context.Context, accountdomain.UserID) (*domain.Credential, error)
}

type passwordConfirmationRepository interface {
	ConfirmPassword(context.Context, accountdomain.UserID, string, string, int64, string) (*sessiondomain.PasswordConfirmation, error)
}

type reauthenticationLimiter interface {
	AllowUser(context.Context, accountdomain.UserID, string) error
}

type reauthenticationTokens interface {
	GenerateToken(...int) (string, error)
	Hash(string) string
}

type Reauthentication struct {
	credentials reauthenticationRepository
	sessions    passwordConfirmationRepository
	hash        hasher
	limit       reauthenticationLimiter
	tokens      reauthenticationTokens
	freshFor    time.Duration
}

func NewReauthentication(credentials reauthenticationRepository, sessions passwordConfirmationRepository, hash hasher, limit reauthenticationLimiter, tokens reauthenticationTokens, freshFor time.Duration) *Reauthentication {
	return &Reauthentication{credentials: credentials, sessions: sessions, hash: hash, limit: limit, tokens: tokens, freshFor: freshFor}
}

type ReauthenticationResult struct {
	Token      string `json:"-"`
	ExpiresAt  time.Time
	ValidUntil time.Time
}

func (s *Reauthentication) Confirm(ctx context.Context, user accountdomain.UserID, sessionHash, password, ip string) (*ReauthenticationResult, error) {
	if !accountdomain.ValidUserID(user) || len(sessionHash) != 64 || password == "" || len(password) > 1024 {
		return nil, accountdomain.ErrFreshAuthRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.limit.AllowUser(ctx, user, ip); err != nil {
		return nil, err
	}
	credential, err := s.credentials.FindUserByUserID(ctx, user)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, accountdomain.ErrFreshAuthRequired
	}
	if err != nil {
		return nil, err
	}
	if err := s.hash.Compare(ctx, password, credential.PasswordHash); err != nil {
		if errors.Is(err, domain.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, accountdomain.ErrFreshAuthRequired
	}
	token, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	proof, err := s.sessions.ConfirmPassword(ctx, user, sessionHash, credential.PasswordHash, credential.AuthVersion, s.tokens.Hash(token))
	if err != nil {
		return nil, err
	}
	until := proof.VerifiedAt.Add(s.freshFor)
	if until.After(proof.ExpiresAt) {
		until = proof.ExpiresAt
	}
	return &ReauthenticationResult{Token: token, ExpiresAt: proof.ExpiresAt, ValidUntil: until}, nil
}
