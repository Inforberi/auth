package service

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type RecoveryRepository interface {
	FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
	SaveRecoveryRequest(context.Context, RecoveryRequest) (*RecoveryCandidate, error)
	FindRecoveryOwner(context.Context, string, string, string) (accountdomain.UserID, error)
	CompleteRecovery(context.Context, RecoveryCompletion) error
}

type RecoveryRequest struct {
	UserID              accountdomain.UserID
	Digest, BindingHash string
	Secret              []byte
	AllowPrimary        func(method, issuer string) bool
}

type RecoveryCandidate struct {
	RequestID string
	Secret    string `json:"-"`
	URI       string `json:"-"`
	ExpiresAt time.Time
}

type Recovery struct {
	repo    RecoveryRepository
	cipher  Cipher
	code    Authenticator
	limit   Limiter
	issuer  string
	cfg     LoginConfig
	enabled bool
}

func NewRecovery(repo RecoveryRepository, cipher Cipher, code Authenticator, limit Limiter, cfg Config, allowPrimary func(string, string) bool) (*Recovery, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if repo == nil || cipher == nil || code == nil || limit == nil {
		return nil, errors.New("invalid MFA recovery configuration")
	}
	if allowPrimary == nil {
		allowPrimary = func(method, _ string) bool { return method == "password" }
	}
	admission := LoginConfig{AllowPrimary: allowPrimary, UserLimitPerMinute: cfg.UserLimitPerMinute, IPLimitPerMinute: cfg.IPLimitPerMinute, GlobalLimitPerMinute: cfg.GlobalLimitPerMinute}
	return &Recovery{repo: repo, cipher: cipher, code: code, limit: limit, issuer: cfg.Issuer, cfg: admission, enabled: cfg.Enabled && cfg.RecoveryEnabled}, nil
}

type StartRecoveryInput struct {
	Token, Binding, IP string
}

func (s *Recovery) Start(ctx context.Context, input StartRecoveryInput) (*RecoveryCandidate, error) {
	if !s.enabled {
		return nil, domain.ErrUnavailable
	}
	if !validLoginToken(input.Token) || !validLoginToken(input.Binding) || len(input.IP) > 64 {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := admitLogin(ctx, s.cipher, s.limit, s.cfg, "recovery-start", input.Token+":"+input.Binding, input.IP, 5); err != nil {
		return nil, err
	}
	digest, binding := s.cipher.Digest("login:"+input.Token), s.cipher.Digest("browser:"+input.Binding)
	user, err := s.repo.FindLoginOwner(ctx, digest, binding)
	if err != nil {
		return nil, err
	}
	allowed, err := s.limit.Allow(ctx, s.cipher.Digest("user:"+string(user)), s.cfg.UserLimitPerMinute, time.Minute)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	if !allowed {
		return nil, domain.ErrLimited
	}
	secret, uri, err := s.code.Generate(s.issuer, string(user))
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	plain := []byte(string(user) + "\x00" + secret)
	defer clear(plain)
	encrypted, err := s.cipher.Seal(plain)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	result, err := s.repo.SaveRecoveryRequest(ctx, RecoveryRequest{
		UserID: user, Digest: digest, BindingHash: binding, Secret: encrypted, AllowPrimary: s.cfg.AllowPrimary,
	})
	if err != nil {
		return nil, err
	}
	result.Secret, result.URI = secret, uri
	return result, nil
}
