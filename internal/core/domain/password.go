package domain

import (
	"errors"
	"unicode"
)

type HashSalt struct {
	Hash []byte
	Salt []byte
}

var (
	ErrPasswordTooShort = errors.New("password too short")
	ErrPasswordTooLong  = errors.New("password too long")
	ErrPasswordNoLetter = errors.New("password must contain at least one letter")
	ErrPasswordNoDigit  = errors.New("password must contain at least one digit")
	ErrPasswordNoUpper  = errors.New("Password must be contain at least one upper letter")
	ErrHashFormat       = errors.New("invalid password hash format")
)

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}

	if len(password) > 128 {
		return ErrPasswordTooLong
	}

	var hasLetter bool
	var hasDigit bool
	var hasUpper bool

	for _, r := range password {
		if unicode.IsLetter(r) {
			hasLetter = true
		}

		if unicode.IsDigit(r) {
			hasDigit = true
		}

		if unicode.IsUpper(r) {
			hasUpper = true
		}

	}

	if !hasLetter {
		return ErrPasswordNoLetter
	}

	if !hasDigit {
		return ErrPasswordNoDigit
	}

	if !hasUpper {
		return ErrPasswordNoUpper
	}

	return nil
}
