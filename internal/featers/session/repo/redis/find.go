package session_redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
	"github.com/redis/go-redis/v9"
)

func (s *SessionRepo) FindSession(ctx context.Context, tokenHash string) (*session_domain.Session, error) {
	key := sessionKey(tokenHash)

	payload, err := s.db.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, session_domain.ErrSessionNotFound
		}

		return nil, fmt.Errorf("get session: %w", err)
	}

	var session session_domain.Session

	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("unmarshal in find session %w", err)
	}

	return &session, nil
}
