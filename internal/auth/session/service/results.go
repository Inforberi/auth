package service

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type ValidateSession struct {
	UserID    accountdomain.UserID `json:"userId"`
	TokenHash string
	ExpiresAt time.Time `json:"expiresAt"`
	Extended  bool
}

type CreateSessionParams struct {
	UserID    accountdomain.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
	TokenHash string
	UserAgent string
	IPAddress string
}
