package service

import (
	"context"
	"time"
)

type RetentionRepository interface {
	PurgeRetention(context.Context, RetentionConfig) (int64, error)
}

type RetentionService struct {
	repo RetentionRepository
	cfg  RetentionConfig
}

func NewRetention(repo RetentionRepository, cfg RetentionConfig) *RetentionService {
	return &RetentionService{repo: repo, cfg: cfg}
}

func (s *RetentionService) Purge(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.PurgeRetention(ctx, s.cfg)
}

func (s *RetentionService) RunRetention(ctx context.Context, report func(error)) {
	// Pace bounded batches; do not drain an entire backlog during startup.
	interval := s.cfg.Interval
	if interval == 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
				report(err)
			}
		}
	}
}
