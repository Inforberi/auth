package password_domain

import "errors"

var (
	ErrNotFound               = errors.New("not found")
	ErrInvalidEmail           = errors.New("Invalid email")
	ErrInvalidEmailOrPassword = errors.New("Invalid email or password")
)
