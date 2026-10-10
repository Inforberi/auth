package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type RecoveryRepo interface {
	IssueReset(context.Context, string, domain.ResetChallenge) error
	ConsumeReset(context.Context, string, string) error
	ClaimResetDelivery(context.Context) (*domain.ResetDelivery, error)
	FinishResetDelivery(context.Context, domain.ResetDelivery, bool) error
}
type RecoveryCipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}
type (
	RecoveryLimiter interface {
		Allow(context.Context, string, int, time.Duration) (bool, error)
	}
	RecoveryMailer interface {
		SendContext(context.Context, string, string, string) error
	}
)

type RecoveryService struct {
	repo    RecoveryRepo
	cipher  RecoveryCipher
	limiter RecoveryLimiter
	mail    RecoveryMailer
	hash    hasher
	cfg     Config
}

func NewRecovery(repo RecoveryRepo, cipher RecoveryCipher, limiter RecoveryLimiter, mail RecoveryMailer, hash hasher, cfg Config) *RecoveryService {
	if cfg.ResetGlobalLimit == 0 {
		cfg.ResetGlobalLimit = 100
	}
	return &RecoveryService{repo: repo, cipher: cipher, limiter: limiter, mail: mail, hash: hash, cfg: cfg}
}

func (r *RecoveryService) limit(ctx context.Context, key string, limit int, window time.Duration) error {
	allowed, err := r.limiter.Allow(ctx, r.cipher.Digest(key), limit, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrRecoveryLimited
	}
	return nil
}
