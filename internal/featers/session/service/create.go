package session_service

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
)

func (s *SessionService) CreateSession(ctx context.Context, userID domain.UserID, userAgent, ip string) (*Session, error) {
	// generate raw token
	rawToken, err := s.token.GenerateSessionToken()
	if err != nil {
		return &Session{}, err
	}

	// hash token
	tokenHash := s.token.Hash(rawToken)

	// calculate expired_at
	now := s.now.NowUTC()
	expiresAt := now.Add(s.cfg.SessionTTL)

	// save session in db
	err = s.repo.CreateSession(
		ctx,
		session_redis.CreateSessionParams{
			UserID:    userID,
			CreatedAt: now,
			ExpiresAt: expiresAt,
			TokenHash: tokenHash,
			UserAgent: userAgent,
			IPAddress: ip,
		})
	if err != nil {
		return &Session{}, fmt.Errorf("service create session %w", err)
	}

	// return raw token
	return &Session{
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil

}
