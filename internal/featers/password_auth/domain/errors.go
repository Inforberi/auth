package password_domain

import "errors"

var (
	ErrNotFound               = errors.New("not found")
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidEmail           = errors.New("Invalid email")
	ErrInvalidEmailOrPassword = errors.New("Invalid email or password")
	ErrSamePassword           = errors.New("new password must be different from current password")
	ErrEmailAlreadyExists     = errors.New("email already exists")
)
