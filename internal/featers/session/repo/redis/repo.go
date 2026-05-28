package session_redis

import (
	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

type SessionRepo struct {
	db *redis.Client
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
