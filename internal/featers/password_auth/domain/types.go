package password_domain

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type FindByEmailResult struct {
	UserID       domain.UserID
	PasswordHash string
}

type FindUserPassword struct {
	PasswordHash string
}

type LoginResult struct {
	UserID    domain.UserID
	Token     string
	ExpiresAt time.Time
}

type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type RegisterResult struct {
	UserID    domain.UserID
	Token     string
	ExpiresAt time.Time
}
