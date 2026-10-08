package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redis "github.com/redis/go-redis/v9"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func (s *SessionRepo) CreateSession(
	ctx context.Context,
	sessionParams sessionservice.CreateSessionParams,
) error {
	sessionKey := sessionKey(sessionParams.TokenHash)
	userSessionsKey := userSessionsKey(sessionParams.UserID)

	pipe := s.db.TxPipeline()

	session := sessiondomain.Session{
		UserID:    sessionParams.UserID,
		UserAgent: sessionParams.UserAgent,
		IPAddress: sessionParams.IPAddress,
		CreatedAt: sessionParams.CreatedAt,
		ExpiresAt: sessionParams.ExpiresAt,
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	pipe.Set(
		ctx,
		sessionKey,
		payload,
		time.Until(sessionParams.ExpiresAt),
	)

	pipe.SAdd(
		ctx,
		userSessionsKey,
		sessionKey,
	)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("create redis session: %w", err)
	}

	return nil
}

func (s *SessionRepo) FindSession(ctx context.Context, tokenHash string) (*sessiondomain.Session, error) {
	key := sessionKey(tokenHash)

	payload, err := s.db.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, sessiondomain.ErrSessionNotFound
		}

		return nil, fmt.Errorf("get session: %w", err)
	}

	var session sessiondomain.Session

	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("unmarshal in find session %w", err)
	}

	return &session, nil
}

type SessionRepo struct {
	db *redis.Client
}

func sessionKey(tokenHash string) string {
	return "session:" + tokenHash
}

func userSessionsKey(userID accountdomain.UserID) string {
	return "user_sessions:" + string(userID)
}

func New(db *redis.Client) *SessionRepo {
	return &SessionRepo{db: db}
}

func (s *SessionRepo) UpdateSession(ctx context.Context, tokenHash string, session *sessiondomain.Session, ttl time.Duration) error {
	sessionKey := sessionKey(tokenHash)

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("update session marshaling")
	}

	if err := s.db.Set(ctx, sessionKey, payload, ttl).Err(); err != nil {
		return fmt.Errorf("extend session: %w", err)
	}

	return nil
}
