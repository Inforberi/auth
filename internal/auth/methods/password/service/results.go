package service

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type LoginResult struct {
	UserID    accountdomain.UserID
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
	UserID    accountdomain.UserID
	Token     string
	ExpiresAt time.Time
}
