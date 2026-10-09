package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalidReset         = errors.New("invalid password reset")
	ErrPasswordConfirmation = errors.New("password confirmation mismatch")
	ErrRecoveryLimited      = errors.New("password recovery rate limited")
)

type ResetChallenge struct {
	Digest    string
	Payload   []byte
	ExpiresAt time.Time
}

type ResetDelivery struct {
	ID       string
	Lease    string
	Payload  []byte
	Attempts int
}
