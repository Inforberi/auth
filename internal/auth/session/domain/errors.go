package domain

import (
	"errors"
)

var (
	ErrSessionNotFound      = errors.New("Session not found")
	ErrSessionExpired       = errors.New("Session expired")
	ErrInvalidSessionID     = errors.New("invalid session ID")
	ErrOwnedSessionNotFound = errors.New("own session not found")
)
