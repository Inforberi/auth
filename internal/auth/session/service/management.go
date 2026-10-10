package service

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

const SessionPageSize = 50

type ManagementRepository interface {
	ListOwnSessions(context.Context, accountdomain.UserID, string, string, int) ([]domain.Session, error)
	RevokeOwnSession(context.Context, accountdomain.UserID, string, string) error
	RevokeOwnSessions(context.Context, accountdomain.UserID, string) error
}

type Management struct{ repo ManagementRepository }

func NewManagement(repo ManagementRepository) *Management { return &Management{repo: repo} }

type SessionPage struct {
	Sessions   []domain.Session
	NextCursor string
}

func (s *Management) List(ctx context.Context, user accountdomain.UserID, callerHash, before string) (*SessionPage, error) {
	if before != "" {
		if err := domain.ValidateID(before); err != nil {
			return nil, err
		}
	}
	sessions, err := s.repo.ListOwnSessions(ctx, user, callerHash, before, SessionPageSize+1)
	if err != nil {
		return nil, err
	}
	page := &SessionPage{Sessions: sessions}
	if len(sessions) > SessionPageSize {
		page.Sessions = sessions[:SessionPageSize]
		page.NextCursor = page.Sessions[SessionPageSize-1].ID
	}
	return page, nil
}

func (s *Management) Revoke(ctx context.Context, user accountdomain.UserID, callerHash, id string) error {
	if err := domain.ValidateID(id); err != nil {
		return err
	}
	return s.repo.RevokeOwnSession(ctx, user, callerHash, id)
}

func (s *Management) LogoutAll(ctx context.Context, user accountdomain.UserID, callerHash string) error {
	return s.repo.RevokeOwnSessions(ctx, user, callerHash)
}
