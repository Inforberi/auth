package domain

import (
	"errors"
)

var (
	ErrSessionNotFound = errors.New("Session not found")
	ErrSessionExpired  = errors.New("Session expired")
)

type SessionID string
