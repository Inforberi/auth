package service

import (
	"context"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type CreateSessionParams struct {
	AuthVersion       int64
	AbsoluteExpiresAt time.Time
	UserID            accountdomain.UserID
	CreatedAt         time.Time
	ExpiresAt         time.Time
	TokenHash         string
	UserAgent         string
	IPAddress         string
}

// RawToken is returned to the caller; only its digest is stored in the ledger.
type CreatedSession struct {
	RawToken  string
	ExpiresAt time.Time
	Challenge *mfaservice.LoginChallenge
}

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
		},
	)
	if err != nil {
		return nil, fmt.Errorf("service create session %w", err)
	}

	return &CreatedSession{
		RawToken:  rawToken,
		ExpiresAt: expiresAt,
	}, nil
}
