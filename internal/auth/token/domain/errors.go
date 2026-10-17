package domain

import "errors"

var (
	ErrInvalidRequest = errors.New("invalid token exchange request")
	ErrForbidden      = errors.New("token scope not allowed")
	ErrRateLimited    = errors.New("token issuance rate limited")
	ErrUnavailable    = errors.New("token issuance unavailable")
)
