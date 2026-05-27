package session_redis

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

type SessionRepo struct {
	db *redis.Client
}

type Session struct {
	UserID    domain.UserID `json:"userId"`
	UserAgent string        `json:"userAgent"`
	IPAddress string        `json:"ipAddress"`
	CreatedAt time.Time     `json:"createdAt"`
	ExpiresAt time.Time     `json:"expiresAt"`
}

func sessionKey(tokenHash string) string {
	return "session:" + tokenHash
}

func userSessionsKey(userID domain.UserID) string {
	return "user_sessions:" + string(userID)
}

func New(db *redis.Client) *SessionRepo {
	return &SessionRepo{db: db}
}
