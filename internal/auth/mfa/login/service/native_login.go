package service

import (
	"context"
	"net/netip"
	"slices"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *Login) StartNative(ctx context.Context, proof mfaservice.PrimaryProof, target mfaservice.NativeTarget, ip string) (*LoginChallenge, error) {
	if proof.Administrative || (proof.Method != "password" && proof.Method != "emailotp") || len(target.Scope) > 64 {
		return nil, domain.ErrProofRequired
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" {
		return nil, domain.ErrProofRequired
	}
	ip = address.Unmap().String()
	target.Scope = slices.Clone(target.Scope)
	slices.Sort(target.Scope)
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return s.startLogin(ctx, proof, ip, &target)
}

// NativeAttempt is server-owned admission/check material, not proof of completed MFA.
// The repository rechecks the owner and consumes the factor under the final transaction.
type NativeAttempt struct {
	Telegram            *TelegramCodeProof
	Email               *EmailCodeProof
	UserID              accountdomain.UserID
	Digest, BindingHash string
	Factor              LoginFactor
	AllowPrimary        func(string, string) bool
}

func (s *Login) PrepareNativeCompletion(ctx context.Context, input CompleteLoginInput) (NativeAttempt, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var attempt NativeAttempt
	if !validCompletion(input) {
		return attempt, domain.ErrInvalidCode
	}
	if err := s.admitLogin(ctx, "complete", input.Token+":"+input.Binding, input.IP, 5); err != nil {
		return attempt, err
	}
	attempt.Digest, attempt.BindingHash = s.cipher.Digest("native-login:"+input.Token), s.cipher.Digest("native-binding:"+input.Binding)
	user, err := s.repo.FindNativeLoginOwner(ctx, attempt.Digest, attempt.BindingHash)
	if err != nil {
		return attempt, err
	}
	if err := s.cfg.AdmitFactorUser(ctx, s.cipher, s.limit, user); err != nil {
		return attempt, err
	}
	attempt.UserID, attempt.Factor, attempt.AllowPrimary = user, s.loginFactor(input.Code, input.Recovery), s.cfg.AllowPrimary
	if !input.Recovery && domain.ValidTelegramCode(input.Code) {
		attempt.Factor = nil
		attempt.Telegram = &TelegramCodeProof{Verifier: TelegramLoginVerifier(s.cipher, string(user), attempt.Digest, input.Code)}
	}
	return attempt, nil
}
