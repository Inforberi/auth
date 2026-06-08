package session_domain

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type Session struct {
	UserID    domain.UserID `json:"userId"`
	UserAgent string        `json:"userAgent"`
	IPAddress string        `json:"ipAddress"`
	CreatedAt time.Time     `json:"createdAt"`
	ExpiresAt time.Time     `json:"expiresAt"`
}

type ValidateSession struct {
	UserID    domain.UserID `json:"userId"`
	TokenHash string
	ExpiresAt time.Time `json:"expiresAt"`
	Extended  bool
}

type CreateSessionParams struct {
	UserID    domain.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
	TokenHash string
	UserAgent string
	IPAddress string
}
