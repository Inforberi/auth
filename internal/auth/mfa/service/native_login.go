package service

import (
	"context"
	"net/netip"
	"slices"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeTarget struct {
	Audience string
	Scope    []accessdomain.PermissionKey
}

func (t NativeTarget) Validate() error {
	if !authjwt.ValidAudience(t.Audience) || len(t.Scope) == 0 || len(t.Scope) > 64 {
		return domain.ErrProofRequired
	}
	size := 0
	for i, key := range t.Scope {
		if !accessdomain.ValidKey(string(key)) || i > 0 && t.Scope[i-1] >= key {
			return domain.ErrProofRequired
		}
		size += len(key) + 1
	}
	if size-1 > 2048 {
		return domain.ErrProofRequired
	}
	return nil
}

func (s *Login) StartNative(ctx context.Context, proof PrimaryProof, target NativeTarget, ip string) (*LoginChallenge, error) {
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
	if err := admitFactorUser(ctx, s.cipher, s.limit, s.cfg.UserLimitPerMinute, user); err != nil {
		return attempt, err
	}
	attempt.UserID, attempt.Factor, attempt.AllowPrimary = user, s.loginFactor(input.Code, input.Recovery), s.cfg.AllowPrimary
	return attempt, nil
}
