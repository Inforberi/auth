package session_service

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type Session struct {
	ID        domain.SessionID
	RawToken  string
	ExpiredAt time.Time
}

func (s *SessionService) CreateSession(ctx context.Context, userID domain.UserID, userAgent, IP string) (*Session, error) {
	// generate raw token
	rawToken, err := s.token.GenerateSessionToken()
	if err != nil {
		return &Session{}, err
	}

	// hash token
	hashToken := s.token.Hash(rawToken)

	// calculate expired_at
	now := s.now.NowUTC()
	expiredAt := now.Add(s.cfg.SessionTTL)

	// save session in db
	session, err := s.repo.CreateSession(
		ctx,
		userID,
		expiredAt,
		hashToken,
		userAgent,
		IP,
	)
	if err != nil {
		return &Session{}, fmt.Errorf("service create session %w", err)
	}

	// return raw token
	return &Session{
		ID:        session,
		RawToken:  rawToken,
		ExpiredAt: expiredAt,
	}, nil

}
