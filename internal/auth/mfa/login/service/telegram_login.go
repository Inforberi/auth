package service

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type TelegramLoginChannel struct {
	Bot        domain.TelegramBotBinding
	TelegramID int64
}

type TelegramLoginIntent struct {
	Proof               mfaservice.PrimaryProof
	Target              *mfaservice.NativeTarget
	Channel             TelegramLoginChannel
	Digest, BindingHash string
	Verifier            string
}

type TelegramLoginRepository interface {
	TelegramLoginChannel(context.Context, mfaservice.PrimaryProof) (TelegramLoginChannel, error)
	SaveTelegramLoginChallenge(context.Context, TelegramLoginIntent, time.Duration) (*LoginChallengeState, error)
	MarkTelegramLoginDelivered(context.Context, TelegramLoginIntent) error
}

type TelegramLoginSender interface {
	SendLoginCode(context.Context, TelegramLoginChannel, string) error
}

type TelegramLoginTokens interface {
	GenerateToken(...int) (string, error)
	GenerateCode() (string, error)
}

type TelegramLogin struct {
	repo   TelegramLoginRepository
	cipher mfaservice.Cipher
	limits mfaservice.Limiter
	tokens TelegramLoginTokens
	sender TelegramLoginSender
	cfg    mfaservice.LoginConfig
}

func NewTelegramLogin(repo TelegramLoginRepository, cipher mfaservice.Cipher, limits mfaservice.Limiter, tokens TelegramLoginTokens, sender TelegramLoginSender, cfg mfaservice.LoginConfig) (*TelegramLogin, error) {
	if repo == nil || cipher == nil || limits == nil || tokens == nil || sender == nil || cfg.Validate() != nil {
		return nil, domain.ErrUnavailable
	}
	return &TelegramLogin{repo: repo, cipher: cipher, limits: limits, tokens: tokens, sender: sender, cfg: cfg}, nil
}

func (s *TelegramLogin) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*LoginChallenge, error) {
	return s.start(ctx, proof, nil, ip)
}

func (s *TelegramLogin) StartNative(ctx context.Context, proof mfaservice.PrimaryProof, target mfaservice.NativeTarget, ip string) (*LoginChallenge, error) {
	if len(target.Scope) > 64 {
		return nil, domain.ErrProofRequired
	}
	target.Scope = slices.Clone(target.Scope)
	slices.Sort(target.Scope)
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return s.start(ctx, proof, &target, ip)
}

func (s *TelegramLogin) start(ctx context.Context, proof mfaservice.PrimaryProof, target *mfaservice.NativeTarget, ip string) (*LoginChallenge, error) {
	address, err := netip.ParseAddr(ip)
	if !mfaservice.ValidPrimary(proof) || proof.Administrative || proof.Method != "password" || err != nil || address.Zone() != "" {
		return nil, domain.ErrProofRequired
	}
	if s.cfg.AllowPrimary != nil && !s.cfg.AllowPrimary(proof.Method, proof.Issuer) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := mfaservice.AdmitLogin(ctx, s.cipher, s.limits, s.cfg, "start", string(proof.UserID), address.Unmap().String(), s.cfg.UserLimitPerMinute); err != nil {
		return nil, err
	}
	if err := mfaservice.AdmitBudgets(ctx, s.limits, []mfaservice.Budget{{Key: s.cipher.Digest("telegram-login:resend:" + string(proof.UserID)), Count: 1}}); err != nil {
		return nil, err
	}
	channel, err := s.repo.TelegramLoginChannel(ctx, proof)
	if err != nil {
		return nil, err
	}
	token, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	binding, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	code, err := s.tokens.GenerateCode()
	if err != nil || !domain.ValidTelegramCode(code) {
		return nil, domain.ErrUnavailable
	}
	prefix, boundPrefix := "login:", "browser:"
	if target != nil {
		prefix, boundPrefix = "native-login:", "native-binding:"
	}
	digest := s.cipher.Digest(prefix + token)
	intent := TelegramLoginIntent{
		Proof: proof, Target: target, Channel: channel, Digest: digest, BindingHash: s.cipher.Digest(boundPrefix + binding),
		Verifier: TelegramLoginVerifier(s.cipher, string(proof.UserID), digest, code),
	}
	state, err := s.saveChallenge(ctx, intent)
	if err != nil {
		return nil, err
	}
	// The challenge transaction has committed; delivery never holds SQL locks.
	if err := s.sender.SendLoginCode(ctx, channel, code); err != nil {
		return nil, domain.ErrUnavailable
	}
	if err := s.repo.MarkTelegramLoginDelivered(ctx, intent); err != nil {
		return nil, err
	}
	return &LoginChallenge{Token: token, Binding: binding, Method: domain.TelegramCode, ExpiresAt: state.ExpiresAt}, nil
}

func TelegramLoginVerifier(cipher mfaservice.Cipher, user, digest, code string) string {
	return cipher.Digest("telegram-login:" + user + ":" + digest + ":" + code)
}

func (s *TelegramLogin) saveChallenge(ctx context.Context, intent TelegramLoginIntent) (*LoginChallengeState, error) {
	ttl := s.cfg.ChallengeTTL
	if s.cfg.ChallengeTTLSource != nil {
		var err error
		ttl, err = s.cfg.ChallengeTTLSource(ctx)
		if err != nil {
			return nil, domain.ErrUnavailable
		}
	}
	return s.repo.SaveTelegramLoginChallenge(ctx, intent, ttl)
}
