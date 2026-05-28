package session_redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
)

func (s *SessionRepo) Create(
	ctx context.Context,
	sessionParams CreateSessionParams,
) error {

	sessionKey := sessionKey(sessionParams.TokenHash)
	userSessionsKey := userSessionsKey(sessionParams.UserID)

	pipe := s.db.TxPipeline()

	session := session_domain.Session{
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
