package domain

import "errors"

var ErrTelegramFactorInUse = errors.New("telegram MFA is configured for users")

type TelegramMFASnapshot struct {
	Version int64
	Allowed bool
}
