package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func (s *SessionRepo) UpdateSession(ctx context.Context, tokenHash string, session *sessionmodel.Session, ttl time.Duration) error {
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
