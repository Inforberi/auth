package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

// PrimaryProof comes from a verified method adapter, never from an HTTP request.
type PrimaryProof struct {
	ProviderVersion int64
	Administrative  bool
	UserID          accountdomain.UserID
	AuthVersion     int64
	Method          string
	Reference       string
	Issuer          string
	VerifiedAt      time.Time
}

type LoginConfig struct {
	Issuer                string
	AllowPrimary          func(method, issuer string) bool
	ChallengeTTL          time.Duration
	SessionTTL            time.Duration
	AbsoluteSessionTTL    time.Duration
	AdminIdleTimeout      time.Duration
	AdminAbsoluteTTL      time.Duration
	AdminActivityInterval time.Duration
	UserLimitPerMinute    int
	IPLimitPerMinute      int
	GlobalLimitPerMinute  int
}

type LoginRepository interface {
	FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
	SaveLoginChallenge(context.Context, PrimaryProof, string, string, time.Duration) (*LoginChallengeState, error)
	CompleteLogin(context.Context, LoginCompletion, LoginFactor) (*LoginCommit, error)
	SaveLoginEnrollment(context.Context, LoginEnrollmentParams) (time.Time, error)
	ConfirmLoginEnrollment(context.Context, LoginEnrollmentParams, Check, []string) error
}

type LoginFactor func(accountdomain.UserID) (Check, string)

type loginTokens interface {
	GenerateToken(...int) (string, error)
	Hash(string) string
}

type Login struct {
	repo   LoginRepository
	cipher Cipher
	code   Authenticator
	limit  Limiter
	tokens loginTokens
	cfg    LoginConfig
}

func NewLogin(repo LoginRepository, cipher Cipher, code Authenticator, limit Limiter, tokens loginTokens, cfg LoginConfig) (*Login, error) {
	if repo == nil || cipher == nil || code == nil || limit == nil || tokens == nil ||
		cfg.ChallengeTTL <= 0 || cfg.ChallengeTTL > 5*time.Minute || cfg.SessionTTL <= 0 ||
		cfg.AbsoluteSessionTTL < cfg.SessionTTL || cfg.UserLimitPerMinute < 2 ||
		cfg.IPLimitPerMinute < 2 || cfg.GlobalLimitPerMinute < 2 {
		return nil, errors.New("invalid MFA login configuration")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "Auth"
	}
	return &Login{repo: repo, cipher: cipher, code: code, limit: limit, tokens: tokens, cfg: cfg}, nil
}

type LoginChallengeState struct {
	ExpiresAt          time.Time
	EnrollmentRequired bool
}

type LoginChallenge struct {
	Token              string `json:"-"`
	Binding            string `json:"-"`
	ExpiresAt          time.Time
	EnrollmentRequired bool
}

func (s *Login) Start(ctx context.Context, proof PrimaryProof, ip string) (*LoginChallenge, error) {
	if !ValidPrimary(proof) || len(ip) > 64 {
		return nil, domain.ErrProofRequired
	}
	if !proof.Administrative && s.cfg.AllowPrimary != nil && !s.cfg.AllowPrimary(proof.Method, proof.Issuer) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admitLogin(ctx, "start", string(proof.UserID), ip, s.cfg.UserLimitPerMinute); err != nil {
		return nil, err
	}
	token, err := randomLoginToken()
	if err != nil {
		return nil, err
	}
	binding, err := randomLoginToken()
	if err != nil {
		return nil, err
	}
	state, err := s.repo.SaveLoginChallenge(ctx, proof, s.cipher.Digest("login:"+token),
		s.cipher.Digest("browser:"+binding), s.cfg.ChallengeTTL)
	if err != nil {
		return nil, err
	}
	return &LoginChallenge{Token: token, Binding: binding, ExpiresAt: state.ExpiresAt, EnrollmentRequired: state.EnrollmentRequired}, nil
}

func ValidPrimary(p PrimaryProof) bool {
	if p.Administrative && p.Method != "password" {
		return false
	}
	if !accountdomain.ValidUserID(p.UserID) || p.AuthVersion < 1 || p.VerifiedAt.IsZero() {
		return false
	}
	switch p.Method {
	case "password":
		return p.Issuer == "" && len(p.Reference) > 0 && len(p.Reference) <= 1024
	case "emailotp":
		return p.Issuer == "" && accountdomain.ValidUserID(accountdomain.UserID(p.Reference))
	case "oidc":
		return (accountdomain.IdentityKey{Issuer: p.Issuer, Subject: p.Reference}).Validate() == nil
	default:
		return false
	}
}

func randomLoginToken() (string, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

func validLoginToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
