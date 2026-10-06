package service

import (
	"context"
	"fmt"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func (s *SessionService) CreateSession(ctx context.Context, userID accountmodel.UserID, userAgent, ip string) (*sessionmodel.CreatedSession, error) {
	// generate raw token
	rawToken, err := s.token.GenerateToken()
	if err != nil {
		return nil, err
	}

	// hash token
	tokenHash := s.token.Hash(rawToken)

	// calculate expired_at
	now := s.now.NowUTC()
	expiresAt := now.Add(s.cfg.SessionTTL)

	// save session in db
	err = s.repo.CreateSession(
		ctx,
		sessionmodel.CreateSessionParams{
			UserID:    userID,
			CreatedAt: now,
			ExpiresAt: expiresAt,
			TokenHash: tokenHash,
			UserAgent: userAgent,
			IPAddress: ip,
		})
	if err != nil {
		return nil, fmt.Errorf("service create session %w", err)
	}

	// return raw token
	return &sessionmodel.CreatedSession{
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil
}
