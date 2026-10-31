package domain

import "errors"

var ErrEmailFactorInUse = errors.New("email MFA is configured for users")

type EmailMFASnapshot struct {
	Version int64
	Allowed bool
}
