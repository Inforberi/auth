package service

import (
	"context"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type RotationRepository interface {
	RotateSession(context.Context, accountdomain.UserID, string, string) (time.Time, error)
}

type Rotation struct {
	repo  RotationRepository
	token tokenManager
}

func NewRotation(repo RotationRepository, token tokenManager) *Rotation {
	return &Rotation{repo: repo, token: token}
}

func (s *Rotation) Rotate(ctx context.Context, user accountdomain.UserID, currentHash string) (*CreatedSession, error) {
	raw, err := s.token.GenerateToken()
	if err != nil {
		return nil, err
	}
	expires, err := s.repo.RotateSession(ctx, user, currentHash, s.token.Hash(raw))
	if err != nil {
		return nil, fmt.Errorf("rotate session: %w", err)
	}
	return &CreatedSession{RawToken: raw, ExpiresAt: expires}, nil
}
