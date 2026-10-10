package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalidEmailChange = errors.New("invalid email change")
	ErrEmailChangePending = errors.New("email change already pending")
	ErrFreshAuthRequired  = errors.New("fresh authentication required")
)

type EmailChangeSnapshot struct {
	UserID       UserID
	EmailID      AddressID
	Email        string
	PasswordHash string
	AuthVersion  AuthVersion
}

type EmailChangeIntent struct {
	ConfirmDigest     string
	ReportDigest      string
	ConfirmPayload    []byte
	NoticePayload     []byte
	CompletionPayload []byte
	ExpiresAt         time.Time
	ProtectUntil      time.Time
}
