package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalidVerification = errors.New("invalid verification")
	ErrVerificationLimited = errors.New("verification rate limited")
	ErrEmailUnverified     = errors.New("email not verified")
)

type Verification struct {
	Digest    string
	Payload   []byte
	ExpiresAt time.Time
}

type VerificationDelivery struct {
	EmailChange bool
	ID          string
	Lease       string
	Payload     []byte
	Attempts    int
}
