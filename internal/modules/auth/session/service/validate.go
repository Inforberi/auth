package service

import (
	"context"
	"fmt"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func (s *SessionService) ValidateSession(ctx context.Context, rawToken string) (*sessionmodel.ValidateSession, error) {
	// hash token
	hashToken := s.token.Hash(rawToken)

	// find session in store
	session, err := s.repo.FindSession(ctx, hashToken)
	if err != nil {
		return nil, fmt.Errorf("FindSession: %w", err)
	}

	now := s.now.NowUTC()
	absoluteTime := session.CreatedAt.Add(s.cfg.AbsoluteSessionTTL)

	// check is active session
	if now.After(session.ExpiresAt) || now.After(absoluteTime) {
		return nil, sessionmodel.ErrSessionExpired
	}

	timeLeft := session.ExpiresAt.Sub(now)

	// update if lost SessionRefreshThreshold<
	if timeLeft <= s.cfg.SessionRefreshThreshold {
		session.ExpiresAt = now.Add(s.cfg.SessionTTL)

		if err := s.repo.UpdateSession(ctx, hashToken, session, s.cfg.SessionTTL); err != nil {
			return nil, fmt.Errorf("UpdateSession: %w", err)
		}

		return &sessionmodel.ValidateSession{
			UserID:    session.UserID,
			TokenHash: hashToken,
			ExpiresAt: session.ExpiresAt,
			Extended:  true,
		}, nil
	}

	return &sessionmodel.ValidateSession{
		UserID:    session.UserID,
		TokenHash: hashToken,
		ExpiresAt: session.ExpiresAt,
		Extended:  false,
	}, nil
}
