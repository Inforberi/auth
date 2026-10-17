package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type ActivityResult struct {
	ExpiresAt time.Time
	Extended  bool
}

type ActivityRepository interface {
	RecordActivity(context.Context, accountdomain.UserID, string) (*ActivityResult, error)
}

type Activity struct{ repo ActivityRepository }

func NewActivity(repo ActivityRepository) *Activity { return &Activity{repo: repo} }

func (s *Activity) Record(ctx context.Context, user accountdomain.UserID, tokenHash string) (*ActivityResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.RecordActivity(ctx, user, tokenHash)
}
