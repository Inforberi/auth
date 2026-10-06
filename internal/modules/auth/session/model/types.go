package model

import (
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type Session struct {
	UserID    accountmodel.UserID `json:"userId"`
	UserAgent string              `json:"userAgent"`
	IPAddress string              `json:"ipAddress"`
	CreatedAt time.Time           `json:"createdAt"`
	ExpiresAt time.Time           `json:"expiresAt"`
}

type ValidateSession struct {
	UserID    accountmodel.UserID `json:"userId"`
	TokenHash string
	ExpiresAt time.Time `json:"expiresAt"`
	Extended  bool
}

type CreateSessionParams struct {
	UserID    accountmodel.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
	TokenHash string
	UserAgent string
	IPAddress string
}
