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
	ExpiresAt time.Time     `json:"expiresAt"`
	Extended  bool
}
