package domain

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Session struct {
	AuthVersion        int64                `json:"-"`
	IdleTimeoutSeconds int64                `json:"-"`
	ID                 string               `json:"id"`
	CredentialProfile  string               `json:"credentialProfile"`
	AbsoluteExpiresAt  time.Time            `json:"absoluteExpiresAt"`
	UserID             accountdomain.UserID `json:"userId"`
	UserAgent          string               `json:"userAgent"`
	IPAddress          string               `json:"ipAddress"`
	CreatedAt          time.Time            `json:"createdAt"`
	ExpiresAt          time.Time            `json:"expiresAt"`
	PrimaryMethod      string               `json:"primaryMethod,omitempty"`
	PrimaryVerifiedAt  *time.Time           `json:"primaryVerifiedAt,omitempty"`
	MFAVerifiedAt      *time.Time           `json:"mfaVerifiedAt,omitempty"`
}

type PasswordConfirmation struct {
	VerifiedAt time.Time
	ExpiresAt  time.Time
}
