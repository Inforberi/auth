package redis

import (
	redis "github.com/redis/go-redis/v9"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type SessionRepo struct {
	db *redis.Client
}

func sessionKey(tokenHash string) string {
	return "session:" + tokenHash
}

func userSessionsKey(userID accountmodel.UserID) string {
	return "user_sessions:" + string(userID)
}

func New(db *redis.Client) *SessionRepo {
	return &SessionRepo{db: db}
}
