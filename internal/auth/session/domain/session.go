package domain

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Session struct {
	UserID    accountdomain.UserID `json:"userId"`
	UserAgent string               `json:"userAgent"`
	IPAddress string               `json:"ipAddress"`
	CreatedAt time.Time            `json:"createdAt"`
	ExpiresAt time.Time            `json:"expiresAt"`
}
