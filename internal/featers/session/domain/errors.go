package session_domain

import "errors"

var (
	ErrSessionNotFound = errors.New("Session not found")
	ErrSessionExpired  = errors.New("Session expired")
)
