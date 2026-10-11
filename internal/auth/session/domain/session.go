package domain

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Session struct {
	ID                string               `json:"id"`
	AbsoluteExpiresAt time.Time            `json:"absoluteExpiresAt"`
	UserID            accountdomain.UserID `json:"userId"`
	UserAgent         string               `json:"userAgent"`
	IPAddress         string               `json:"ipAddress"`
	CreatedAt         time.Time            `json:"createdAt"`
	ExpiresAt         time.Time            `json:"expiresAt"`
}

type PasswordConfirmation struct {
	VerifiedAt time.Time
	ExpiresAt  time.Time
}
