package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	redis "github.com/redis/go-redis/v9"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func (s *SessionRepo) FindSession(ctx context.Context, tokenHash string) (*sessionmodel.Session, error) {
	key := sessionKey(tokenHash)

	payload, err := s.db.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, sessionmodel.ErrSessionNotFound
		}

		return nil, fmt.Errorf("get session: %w", err)
	}

	var session sessionmodel.Session

	if err := json.Unmarshal(payload, &session); err != nil {
		return nil, fmt.Errorf("unmarshal in find session %w", err)
	}

	return &session, nil
}
