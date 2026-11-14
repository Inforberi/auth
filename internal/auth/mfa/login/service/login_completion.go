package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type CompleteLoginInput struct {
	Token, Binding, Code string
	Recovery             bool
	UserAgent, IP        string
}

type LoginCompletion struct {
	Telegram                         *TelegramCodeProof
	Email                            *EmailCodeProof
	AllowPrimary                     func(method, issuer string) bool
	Digest, BindingHash, SessionHash string
	UserAgent, IP                    string
	SessionTTL, AbsoluteSessionTTL   time.Duration
	AdminIdleTimeout                 time.Duration
	AdminAbsoluteTTL                 time.Duration
	AdminActivityInterval            time.Duration
}

type TelegramCodeProof struct{ Verifier string }

// EmailCodeProof contains scoped verifiers, not an assertion that a factor passed.
type EmailCodeProof struct {
	Digest   string
	Verifier string
}

type LoginCommit struct {
	UserID      accountdomain.UserID
	ExpiresAt   time.Time
	MFAVerified time.Time
}

type LoginSession struct {
	Token       string `json:"-"`
	UserID      accountdomain.UserID
	ExpiresAt   time.Time
	MFAVerified time.Time
}

func (s *Login) Complete(ctx context.Context, input CompleteLoginInput) (*LoginSession, error) {
	if !validCompletion(input) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// User attempts are enforced by the locked SQL challenge; wrong browser bindings cannot burn them.
	if err := s.admitLogin(ctx, "complete", input.Token+":"+input.Binding, input.IP, 5); err != nil {
		return nil, err
	}
	digest, binding := s.cipher.Digest("login:"+input.Token), s.cipher.Digest("browser:"+input.Binding)
	user, err := s.repo.FindLoginOwner(ctx, digest, binding)
	if err != nil {
		return nil, err
	}
	// This counter spans all primary logins: replacing a challenge cannot reset guessing admission.
	if err := s.cfg.AdmitFactorUser(ctx, s.cipher, s.limit, user); err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	// The repository owns the challenge's user, not a caller-supplied UUID.
	factor := s.loginFactor(input.Code, input.Recovery)
	var telegram *TelegramCodeProof
	if !input.Recovery && domain.ValidTelegramCode(input.Code) {
		telegram = &TelegramCodeProof{Verifier: TelegramLoginVerifier(s.cipher, string(user), digest, input.Code)}
		factor = nil
	}
	result, err := s.repo.CompleteLogin(ctx, LoginCompletion{
		Telegram:     telegram,
		AllowPrimary: s.cfg.AllowPrimary,
		Digest:       digest, BindingHash: binding,
		SessionHash: s.tokens.Hash(raw), UserAgent: input.UserAgent, IP: input.IP,
		SessionTTL: s.cfg.SessionTTL, AbsoluteSessionTTL: s.cfg.AbsoluteSessionTTL,
		AdminIdleTimeout:      s.cfg.AdminIdleTimeout,
		AdminAbsoluteTTL:      s.cfg.AdminAbsoluteTTL,
		AdminActivityInterval: s.cfg.AdminActivityInterval,
	}, factor)
	if err != nil {
		return nil, err
	}
	return &LoginSession{Token: raw, UserID: result.UserID, ExpiresAt: result.ExpiresAt, MFAVerified: result.MFAVerified}, nil
}

func validCompletion(input CompleteLoginInput) bool {
	return mfaservice.ValidToken(input.Token) && mfaservice.ValidToken(input.Binding) &&
		((input.Recovery && domain.ValidRecoveryCode(input.Code)) || (!input.Recovery && (domain.ValidCode(input.Code) || domain.ValidTelegramCode(input.Code)))) &&
		len(input.UserAgent) <= 512 && len(input.IP) <= 64
}

func (s *Login) loginFactor(code string, recovery bool) LoginFactor {
	return func(user accountdomain.UserID) (mfaservice.Check, string) {
		digest := ""
		if recovery {
			digest = s.cipher.Digest("recovery:" + string(user) + ":" + code)
		}
		return mfaservice.FactorCheck(s.cipher, s.code, user, code), digest
	}
}

func (s *Login) admitLogin(ctx context.Context, purpose, subject, ip string, count int) error {
	return mfaservice.AdmitLogin(ctx, s.cipher, s.limit, s.cfg, purpose, subject, ip, count)
}
