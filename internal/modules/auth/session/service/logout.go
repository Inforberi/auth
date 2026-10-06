package service

import (
	"context"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

func (s *SessionService) Logout(ctx context.Context, tokenHash string, userID accountmodel.UserID) error {
	return s.repo.DeleteSession(ctx, tokenHash, userID)
}

func (s *SessionService) LogoutAll(ctx context.Context, tokenHash string, userID accountmodel.UserID) error {
	return s.repo.DeleteAllSessions(ctx, userID)
}

func (s *SessionService) LogoutAllExcept(ctx context.Context, tokenHash string, userID accountmodel.UserID) error {
	return s.repo.DeleteAllSessionsExcept(ctx, userID, tokenHash)
}
