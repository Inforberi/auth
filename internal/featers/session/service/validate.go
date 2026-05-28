package session_service

import (
	"context"
	"fmt"

	session_domain "github.com/Inforberi/financial-intelligence/internal/featers/session/domain"
)

func (s *SessionService) ValidateSession(ctx context.Context, rawToken string) (*session_domain.ValidateSession, error) {
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
		return nil, session_domain.ErrSessionExpired
	}

	timeLeft := session.ExpiresAt.Sub(now)

	if timeLeft <= s.cfg.SessionRefreshThreshold {
		session.ExpiresAt = now.Add(s.cfg.SessionTTL)

		if err := s.repo.UpdateSession(ctx, hashToken, session, s.cfg.SessionTTL); err != nil {
			return nil, fmt.Errorf("UpdateSession: %w", err)
		}

		return &session_domain.ValidateSession{
			UserID:    session.UserID,
			ExpiresAt: session.ExpiresAt,
			Extended:  true,
		}, nil
	}

	return &session_domain.ValidateSession{
		UserID:    session.UserID,
		ExpiresAt: session.ExpiresAt,
		Extended:  false,
	}, nil
}
