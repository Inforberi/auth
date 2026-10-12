package domain

import (
	"errors"
)

var (
	ErrSessionNotFound      = errors.New("Session not found")
	ErrMFARequired          = errors.New("second factor required before session issuance")
	ErrSessionExpired       = errors.New("Session expired")
	ErrInvalidSessionID     = errors.New("invalid session ID")
	ErrOwnedSessionNotFound = errors.New("own session not found")
)
