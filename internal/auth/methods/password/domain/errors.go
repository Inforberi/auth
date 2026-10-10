package domain

import (
	"errors"
)

var (
	ErrHashBusy               = errors.New("password hashing capacity exhausted")
	ErrLoginLimited           = errors.New("login rate limited")
	ErrLoginUnavailable       = errors.New("login limiter unavailable")
	ErrPasswordRequired       = errors.New("password required")
	ErrNotFound               = errors.New("not found")
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidEmail           = errors.New("invalid email")
	ErrInvalidEmailOrPassword = errors.New("invalid email or password")
	ErrSamePassword           = errors.New("new password must be different from current password")
	ErrEmailAlreadyExists     = errors.New("email already exists")
)
