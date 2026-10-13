package service

import (
	"context"
	"strings"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type VerifyInput struct {
	UserID      accountdomain.UserID
	AuthVersion int64
	Code        string
	Recovery    bool
}

// Verify consumes a factor, not a login authority. Public callers need the bound challenge flow.
func (s *Service) Verify(ctx context.Context, input VerifyInput) (time.Time, error) {
	if !accountdomain.ValidUserID(input.UserID) || input.AuthVersion < 1 ||
		(input.Recovery && !domain.ValidRecoveryCode(input.Code)) || (!input.Recovery && !domain.ValidCode(input.Code)) {
		return time.Time{}, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.UserID); err != nil {
		return time.Time{}, err
	}
	digest := ""
	if input.Recovery {
		digest = s.cipher.Digest("recovery:" + string(input.UserID) + ":" + input.Code)
	}
	return s.repo.Consume(ctx, input.UserID, input.AuthVersion, s.check(input.UserID, input.Code), digest)
}

func (s *Service) check(user accountdomain.UserID, code string) Check {
	return factorCheck(s.cipher, s.code, user, code)
}

func factorCheck(cipher Cipher, authenticator Authenticator, user accountdomain.UserID, code string) Check {
	return func(encrypted []byte, lastStep int64, now time.Time) (int64, error) {
		plain, err := cipher.Open(encrypted)
		if err != nil {
			return 0, domain.ErrUnavailable
		}
		defer clear(plain)
		owner, secret, found := strings.Cut(string(plain), "\x00")
		if !found || owner != string(user) {
			return 0, domain.ErrUnavailable
		}
		return authenticator.Match(secret, code, now, lastStep)
	}
}
