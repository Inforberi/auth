package session_postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

func (s *SessionRepo) CreateSession(ctx context.Context, userID domain.UserID, expiredTime time.Time, tokenHash, userAgent, IP string) (domain.SessionID, error) {
	sql := `
INSERT INTO auth.sessions(
	user_id,
	token_hash,
	expired_at,
	user_agent,
	ip_address
)
VALUES ($1, $2, $3, $4, $5)
RETURNING id
`
	var sessionID domain.SessionID

	err := s.db.QueryRow(
		ctx,
		sql,
		userID,
		tokenHash,
		expiredTime,
		userAgent,
		IP,
	).Scan(&sessionID)
	if err != nil {
		return "", fmt.Errorf("error create session %w", err)
	}

	return sessionID, nil
}
