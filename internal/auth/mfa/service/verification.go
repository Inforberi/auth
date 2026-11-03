package service

import (
	"strings"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func FactorCheck(cipher Cipher, authenticator Authenticator, user accountdomain.UserID, code string) Check {
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
