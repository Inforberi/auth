package register_service

import "errors"

var (
	ErrEmailAlreadyExists = errors.New("email already exists")
)
