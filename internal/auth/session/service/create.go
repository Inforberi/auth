package service

import (
	"context"
	"fmt"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *SessionService) CreateSessionAtVersion(ctx context.Context, userID accountdomain.UserID, userAgent, ip string, version int64) (*CreatedSession, error) {
	rawToken, err := s.token.GenerateToken()
	if err != nil {
		return nil, err
	}

	tokenHash := s.token.Hash(rawToken)

	now := s.now.NowUTC()
	expiresAt := now.Add(s.cfg.SessionTTL)

	err = s.repo.CreateSession(
		ctx,
		CreateSessionParams{
			AuthVersion:       version,
			AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteSessionTTL),
			UserID:            userID,
			CreatedAt:         now,
			ExpiresAt:         expiresAt,
			TokenHash:         tokenHash,
			UserAgent:         userAgent,
			IPAddress:         ip,
		})
	if err != nil {
		return nil, fmt.Errorf("service create session %w", err)
	}

	return &CreatedSession{
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil
}
