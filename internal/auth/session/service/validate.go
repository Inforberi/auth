package service

import (
	"context"
	"fmt"

	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func (s *SessionService) ValidateSession(ctx context.Context, rawToken string) (*ValidateSession, error) {
	hashToken := s.token.Hash(rawToken)

	session, err := s.repo.FindSession(ctx, hashToken)
	if err != nil {
		return nil, fmt.Errorf("FindSession: %w", err)
	}

	now := s.now.NowUTC()
	absoluteTime := session.CreatedAt.Add(s.cfg.AbsoluteSessionTTL)
	if !session.AbsoluteExpiresAt.IsZero() {
		absoluteTime = session.AbsoluteExpiresAt
	}

	if !now.Before(session.ExpiresAt) || !now.Before(absoluteTime) {
		return nil, sessiondomain.ErrSessionExpired
	}

	timeLeft := session.ExpiresAt.Sub(now)

	if timeLeft <= s.cfg.SessionRefreshThreshold {
		session.ExpiresAt = now.Add(s.cfg.SessionTTL)
		if session.ExpiresAt.After(absoluteTime) {
			session.ExpiresAt = absoluteTime
		}

		if err := s.repo.UpdateSession(ctx, hashToken, session, session.ExpiresAt.Sub(now)); err != nil {
			return nil, fmt.Errorf("UpdateSession: %w", err)
		}

		return &ValidateSession{
			UserID:    session.UserID,
			TokenHash: hashToken,
			ExpiresAt: session.ExpiresAt,
			Extended:  true,
		}, nil
	}

	return &ValidateSession{
		UserID:    session.UserID,
		TokenHash: hashToken,
		ExpiresAt: session.ExpiresAt,
		Extended:  false,
	}, nil
}
