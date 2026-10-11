package domain

import (
	"errors"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

var (
	ErrTemporaryPasswordDisabled = errors.New("temporary password profile disabled")
	ErrInvalidTemporaryPassword  = errors.New("invalid temporary password authority")
	ErrTemporaryPasswordReuse    = errors.New("permanent password must differ from temporary password")
	ErrTemporaryPasswordCooldown = errors.New("temporary password reissue cooldown")
)

type TemporaryCredential struct {
	UserID       accountdomain.UserID
	EmailID      accountdomain.AddressID
	AuthVersion  int64
	PasswordHash string
	SecretDigest string
}
