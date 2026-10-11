package service

import (
	"context"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type ValidationResult struct {
	SessionID string
	UserID    accountdomain.UserID `json:"userId"`
	TokenHash string
	ExpiresAt time.Time `json:"expiresAt"`
	Extended  bool
}

func (s *SessionService) ValidateSession(ctx context.Context, rawToken string) (*ValidationResult, error) {
	return s.validateSession(ctx, rawToken, true)
}

func (s *SessionService) ValidateSessionWithoutRefresh(ctx context.Context, rawToken string) (*ValidationResult, error) {
	return s.validateSession(ctx, rawToken, false)
}

func (s *SessionService) validateSession(ctx context.Context, rawToken string, refresh bool) (*ValidationResult, error) {
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
	extended := false

	if refresh && timeLeft <= s.cfg.SessionRefreshThreshold {
		candidate := now.Add(s.cfg.SessionTTL)
		if candidate.After(absoluteTime) {
			candidate = absoluteTime
		}
		if candidate.After(session.ExpiresAt) {
			expected := session.ExpiresAt
			session.ExpiresAt = candidate
			extended, err = s.repo.RefreshSession(ctx, hashToken, session, expected)
			if err != nil {
				return nil, fmt.Errorf("RefreshSession: %w", err)
			}
		}
	}

	return &ValidationResult{
		SessionID: session.ID,
		UserID:    session.UserID,
		TokenHash: hashToken,
		ExpiresAt: session.ExpiresAt,
		Extended:  extended,
	}, nil
}
