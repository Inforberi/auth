package session_redis

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type CreateSessionParams struct {
	UserID    domain.UserID
	CreatedAt time.Time
	ExpiresAt time.Time
	TokenHash string
	UserAgent string
	IPAddress string
}
