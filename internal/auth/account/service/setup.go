package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type SetupConfig struct {
	Enabled bool   `env:"INITIAL_SETUP_ENABLED" env-default:"false"`
	Secret  string `env:"INITIAL_SETUP_SECRET"`
}

func (c SetupConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Secret)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != c.Secret {
		return fmt.Errorf("INITIAL_SETUP_SECRET must encode 32 random bytes in unpadded base64url")
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	if nonzero == 0 {
		return fmt.Errorf("INITIAL_SETUP_SECRET must not be zero")
	}
	return nil
}

type SetupCheck func([]byte, time.Time) (*domain.SetupAccount, error)

type setupRepository interface {
	CheckSetupOpen(context.Context) error
	SaveSetup(context.Context, string, string, []byte) (time.Time, error)
	CompleteSetup(context.Context, string, string, SetupCheck) error
}

type setupHasher interface {
	GenerateHash(context.Context, []byte) (string, error)
}

type SetupService struct {
	repo                 setupRepository
	limiter              Limiter
	cipher, factorCipher Cipher
	mail                 Mailer
	hash                 setupHasher
	code                 mfaservice.Authenticator
	cfg                  SetupConfig
	issuer               string
}

func NewSetup(repo setupRepository, limits Limiter, cipher, factorCipher Cipher, mail Mailer, hash setupHasher, code mfaservice.Authenticator, cfg SetupConfig, issuer string) (*SetupService, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled || repo == nil || limits == nil || cipher == nil || factorCipher == nil || mail == nil || hash == nil || code == nil || issuer == "" {
		return nil, domain.ErrSetupClosed
	}
	return &SetupService{repo: repo, limiter: limits, cipher: cipher, factorCipher: factorCipher, mail: mail, hash: hash, code: code, cfg: cfg, issuer: issuer}, nil
}

func (s *SetupService) admit(ctx context.Context, secret, ip, action string) error {
	for _, budget := range []struct {
		key   string
		count int
	}{{"ip:" + ip, 10}, {"project", 30}} {
		ok, err := s.limiter.Allow(ctx, s.cipher.Digest("initial-setup:"+action+":"+budget.key), budget.count, time.Minute)
		if err != nil {
			return domain.ErrDependencyUnavailable
		}
		if !ok {
			return domain.ErrVerificationLimited
		}
	}
	if len(secret) != 43 || subtle.ConstantTimeCompare([]byte(tokenDigest(secret)), []byte(tokenDigest(s.cfg.Secret))) != 1 {
		return domain.ErrSetupUnauthorized
	}
	return s.repo.CheckSetupOpen(ctx)
}

type setupPayload struct {
	UserID                                   domain.UserID
	Email, PasswordHash, Secret, EmailDigest string
}
