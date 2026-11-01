package service

import (
	"context"
	"net/netip"
	"slices"
	"time"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *EmailLogin) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*mfaservice.LoginChallenge, error) {
	return s.start(ctx, proof, nil, ip)
}

func (s *EmailLogin) StartNative(ctx context.Context, proof mfaservice.PrimaryProof, target mfaservice.NativeTarget, ip string) (*mfaservice.LoginChallenge, error) {
	if len(target.Scope) > 64 {
		return nil, mfadomain.ErrProofRequired
	}
	target.Scope = slices.Clone(target.Scope)
	slices.Sort(target.Scope)
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return s.start(ctx, proof, &target, ip)
}

func (s *EmailLogin) start(ctx context.Context, proof mfaservice.PrimaryProof, target *mfaservice.NativeTarget, ip string) (*mfaservice.LoginChallenge, error) {
	if !mfaservice.ValidPrimary(proof) || proof.Administrative || proof.Method != "password" || len(ip) > 64 {
		return nil, mfadomain.ErrProofRequired
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return nil, mfadomain.ErrProofRequired
	}
	ip = address.Unmap().String()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if s.cfg.AllowPrimary != nil && !s.cfg.AllowPrimary(proof.Method, proof.Issuer) {
		return nil, mfadomain.ErrProofRequired
	}
	if err := s.admit(ctx, "start", string(proof.UserID), ip, s.cfg.UserLimitPerMinute); err != nil {
		return nil, err
	}
	allowed, err := s.limits.Allow(ctx, s.mfa.Digest(emailLoginPurpose+"resend:"+string(proof.UserID)), 1, time.Minute)
	if err != nil {
		return nil, mfadomain.ErrUnavailable
	}
	if !allowed {
		return nil, mfadomain.ErrLimited
	}
	channel, err := s.repo.EmailLoginChannel(ctx, proof)
	if err != nil {
		return nil, err
	}
	requested, code, err := prepareCode(s.mail, s.tokens, s.cfg.ChallengeTTL, channel.Email, "подтверждения входа", emailLoginPurpose)
	if err != nil {
		return nil, err
	}
	binding, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	digest, bindingHash := s.identifiers(requested.Binding, binding, target != nil)
	state, err := s.repo.SaveEmailLoginChallenge(ctx, EmailLoginIntent{Proof: proof, Target: target, Channel: channel, Digest: digest, BindingHash: bindingHash, Code: code}, s.cfg.ChallengeTTL)
	if err != nil {
		return nil, err
	}
	return &mfaservice.LoginChallenge{Method: mfadomain.EmailCode, Token: requested.Binding, Binding: binding, ExpiresAt: state.ExpiresAt}, nil
}
