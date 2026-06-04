package session_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

func (s *SessionService) Logout(ctx context.Context, tokenHash string, userID domain.UserID) error {
	return s.repo.DeleteSession(ctx, tokenHash, userID)
}

func (s *SessionService) LogoutAll(ctx context.Context, tokenHash string, userID domain.UserID) error {
	return s.repo.DeleteAllSessions(ctx, userID)
}

func (s *SessionService) LogoutAllExcept(ctx context.Context, tokenHash string, userID domain.UserID) error {
	return s.repo.DeleteAllSessionsExcept(ctx, userID, tokenHash)
}
