package domain

import (
	"encoding/base64"
	"errors"
	"time"
)

var (
	ErrDisabled    = errors.New("email OTP disabled")
	ErrInvalidCode = errors.New("invalid email login")
	ErrLimited     = errors.New("email OTP rate limited")
)

const MaxAttempts = 5

type Challenge struct {
	Digest    string
	Verifier  string
	Payload   []byte
	ExpiresAt time.Time
}

type Delivery struct {
	ID       string
	Lease    string
	Payload  []byte
	Attempts int
}

func ValidBinding(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func ValidCode(value string) bool {
	if len(value) != 8 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
