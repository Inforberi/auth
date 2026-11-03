package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type temporaryRepository interface {
	FindTemporaryProvision(context.Context, accountprovisioning.ProvisionCommand) (*TemporaryIssueResult, error)
	FindTemporaryReissue(context.Context, TemporaryReissueInput) (*TemporaryIssueResult, error)
	ProvisionTemporary(context.Context, accountprovisioning.ProvisionCommand, domain.TemporaryCredential, time.Duration) (*TemporaryIssueResult, error)
	ReissueTemporary(context.Context, TemporaryReissueInput, domain.TemporaryCredential, time.Duration, time.Duration) (*TemporaryIssueResult, error)
	FindTemporary(context.Context, string) (*domain.TemporaryCredential, error)
	BeginTemporary(context.Context, domain.TemporaryCredential, string, time.Duration) (time.Time, error)
	CheckTemporarySetup(context.Context, string) (*domain.TemporaryCredential, error)
	CompleteTemporary(context.Context, string, string) error
}

type TemporaryPasswordService struct {
	repo       temporaryRepository
	hash       passwordservice.Hasher
	limiter    passwordservice.RecoveryLimiter
	digest     func(string) string
	loginLimit passwordservice.LoginLimiter
	cfg        TemporaryPasswordConfig
}

func NewTemporaryPassword(repo temporaryRepository, hash passwordservice.Hasher, limiter passwordservice.RecoveryLimiter, digest func(string) string, loginLimit passwordservice.LoginLimiter, cfg TemporaryPasswordConfig) *TemporaryPasswordService {
	return &TemporaryPasswordService{repo: repo, hash: hash, limiter: limiter, digest: digest, loginLimit: loginLimit, cfg: cfg}
}

func temporarySecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *TemporaryPasswordService) limit(ctx context.Context, key string, attempts int) error {
	return passwordservice.LimitAttempts(ctx, s.limiter, s.digest, key, attempts, time.Minute)
}
