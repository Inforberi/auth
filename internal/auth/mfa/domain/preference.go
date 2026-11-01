package domain

import "errors"

var ErrInvalidPreference = errors.New("invalid MFA preference")

type Preference struct {
	Version int64
	Method  Method
}

func ValidPreference(method Method) bool {
	return method == "" || method == TOTP || method == EmailCode || method == TelegramCode
}
