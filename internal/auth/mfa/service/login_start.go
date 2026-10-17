package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func (s *Login) Start(ctx context.Context, proof PrimaryProof, ip string) (*LoginChallenge, error) {
	return s.startLogin(ctx, proof, ip, nil)
}

func (s *Login) startLogin(ctx context.Context, proof PrimaryProof, ip string, target *NativeTarget) (*LoginChallenge, error) {
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
	var state *LoginChallengeState
	if target == nil {
		state, err = s.repo.SaveLoginChallenge(ctx, proof, s.cipher.Digest("login:"+token), s.cipher.Digest("browser:"+binding), s.cfg.ChallengeTTL)
	} else {
		state, err = s.repo.SaveNativeLoginChallenge(ctx, proof, *target, s.cipher.Digest("native-login:"+token), s.cipher.Digest("native-binding:"+binding), s.cfg.ChallengeTTL)
	}
	if err != nil {
		return nil, err
	}
	return &LoginChallenge{Token: token, Binding: binding, ExpiresAt: state.ExpiresAt, EnrollmentRequired: state.EnrollmentRequired}, nil
}
