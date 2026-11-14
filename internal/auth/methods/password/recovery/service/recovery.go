package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type RecoveryRepo interface {
	IssueReset(context.Context, string, domain.ResetChallenge) error
	ConsumeReset(context.Context, string, string) error
	ClaimResetDelivery(context.Context) (*domain.ResetDelivery, error)
	FinishResetDelivery(context.Context, domain.ResetDelivery, bool) error
}

type RecoveryMailer interface {
	SendContext(context.Context, string, string, string) error
}

type RecoveryService struct {
	repo    RecoveryRepo
	cipher  passwordservice.RecoveryCipher
	limiter passwordservice.RecoveryLimiter
	mail    RecoveryMailer
	hash    passwordservice.Hasher
	cfg     Config
}

func NewRecovery(repo RecoveryRepo, cipher passwordservice.RecoveryCipher, limiter passwordservice.RecoveryLimiter, mail RecoveryMailer, hash passwordservice.Hasher, cfg Config) *RecoveryService {
	if cfg.ResetGlobalLimit == 0 {
		cfg.ResetGlobalLimit = 100
	}
	return &RecoveryService{repo: repo, cipher: cipher, limiter: limiter, mail: mail, hash: hash, cfg: cfg}
}

func (r *RecoveryService) limit(ctx context.Context, key string, limit int, window time.Duration) error {
	return passwordservice.LimitAttempts(ctx, r.limiter, r.cipher.Digest, key, limit, window)
}

func (r *RecoveryService) limitGlobalReset(ctx context.Context) error {
	limit := r.cfg.ResetGlobalLimit
	if r.cfg.ResetBudgetSource != nil {
		var err error
		limit, err = r.cfg.ResetBudgetSource(ctx)
		if err != nil {
			return err
		}
	}
	return r.limit(ctx, "reset-global", limit, time.Minute)
}
