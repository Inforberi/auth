package service

import (
	"context"
	"time"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type RetentionRepository interface {
	PurgeRetention(context.Context, RetentionConfig) (int64, error)
}

type RetentionSettings interface {
	Current(context.Context) (settingsdomain.RetentionPolicy, error)
}

type RetentionService struct {
	repo     RetentionRepository
	cfg      RetentionConfig
	settings RetentionSettings
}

func NewRetention(repo RetentionRepository, cfg RetentionConfig) *RetentionService {
	return &RetentionService{repo: repo, cfg: cfg}
}

func (s *RetentionService) WithSettings(source RetentionSettings) *RetentionService {
	s.settings = source
	return s
}

func (s *RetentionService) Purge(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg := s.cfg
	if s.settings != nil {
		policy, err := s.settings.Current(ctx)
		if err != nil {
			return 0, err
		}
		cfg.EmailReservationDays, cfg.SessionDays, cfg.SecurityAuditDays = policy.EmailReservationDays, policy.SessionDays, policy.SecurityAuditDays
	}
	return s.repo.PurgeRetention(ctx, cfg)
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
