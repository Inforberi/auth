package service

import (
	"context"
	"encoding/hex"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type Proof struct {
	UserID      accountdomain.UserID
	TokenHash   string
	AuthVersion int64
}

type Check func(encrypted []byte, lastStep int64, now time.Time) (int64, error)

type Repository interface {
	SaveEnrollment(context.Context, Proof, string, []byte) (time.Time, error)
	ConfirmEnrollment(context.Context, Proof, string, Check, []string) error
	Consume(context.Context, accountdomain.UserID, int64, Check, string) (time.Time, error)
}

type Cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}

type Authenticator interface {
	Generate(string, string) (string, string, error)
	Match(string, string, time.Time, int64) (int64, error)
}

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type Service struct {
	repo   Repository
	cipher Cipher
	code   Authenticator
	limit  Limiter
	issuer string
}

func New(repo Repository, cipher Cipher, code Authenticator, limit Limiter, issuer string) *Service {
	return &Service{repo: repo, cipher: cipher, code: code, limit: limit, issuer: issuer}
}

func validProof(proof Proof) bool {
	if len(proof.TokenHash) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(proof.TokenHash)
	return accountdomain.ValidUserID(proof.UserID) && proof.AuthVersion > 0 && err == nil && len(decoded) == 32
}

func (s *Service) admit(ctx context.Context, user accountdomain.UserID) error {
	if s.limit == nil {
		return domain.ErrUnavailable
	}
	for _, budget := range []struct {
		key   string
		count int
	}{
		{s.cipher.Digest("user:" + string(user)), 5}, {"project", 500},
	} {
		allowed, err := s.limit.Allow(ctx, budget.key, budget.count, time.Minute)
		if err != nil {
			return domain.ErrUnavailable
		}
		if !allowed {
			return domain.ErrLimited
		}
	}
	return nil
}
