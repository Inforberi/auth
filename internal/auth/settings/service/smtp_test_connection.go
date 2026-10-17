package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

var (
	ErrSMTPTestLimited = errors.New("SMTP connection test limited")
	ErrSMTPTestFailed  = errors.New("SMTP connection test failed")
)

func (s *SMTP) TestConnection(ctx context.Context, actor accessservice.Principal, expectedVersion int64) error {
	if actor.Validate() != nil {
		return accessdomain.ErrForbidden
	}
	if expectedVersion < 1 {
		return domain.ErrInvalidSMTP
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case s.tests <- struct{}{}:
		defer func() { <-s.tests }()
	default:
		return ErrSMTPTestLimited
	}
	stored, err := s.repo.AuthorizeSMTPTest(ctx, actor, expectedVersion)
	if err != nil {
		return err
	}
	for _, budget := range []struct {
		key string
		max int
	}{{"user:" + string(actor.UserID), 3}, {"project", 10}} {
		allowed, err := s.limits.Allow(ctx, budget.key, budget.max, time.Minute)
		if err != nil {
			return errors.New("SMTP test limiter unavailable")
		}
		if !allowed {
			return ErrSMTPTestLimited
		}
	}
	config, password, err := s.open(stored)
	if err != nil {
		return err
	}
	// Authorization transaction has committed; SMTP must never hold Access/user locks.
	if err := s.probe(ctx, config, password); err != nil {
		return ErrSMTPTestFailed
	}
	return nil
}
