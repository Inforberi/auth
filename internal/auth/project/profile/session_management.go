package profile

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (s *SessionRuntime) List(ctx context.Context, user accountdomain.UserID, hash, before string) (*sessionservice.SessionPage, error) {
	var result *sessionservice.SessionPage
	err := s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		var err error
		result, err = sessionservice.NewManagement(repo).List(ctx, user, hash, before)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SessionRuntime) Revoke(ctx context.Context, user accountdomain.UserID, hash, id string) error {
	return s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		return sessionservice.NewManagement(repo).Revoke(ctx, user, hash, id)
	})
}

func (s *SessionRuntime) LogoutAll(ctx context.Context, user accountdomain.UserID, hash string) error {
	return s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		return sessionservice.NewManagement(repo).LogoutAll(ctx, user, hash)
	})
}

func (s *SessionRuntime) Record(ctx context.Context, user accountdomain.UserID, hash string) (*sessionservice.ActivityResult, error) {
	var result *sessionservice.ActivityResult
	err := s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		var err error
		result, err = sessionservice.NewActivity(repo).Record(ctx, user, hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SessionRuntime) Rotate(ctx context.Context, user accountdomain.UserID, hash string) (*sessionservice.CreatedSession, error) {
	var result *sessionservice.CreatedSession
	err := s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		var err error
		result, err = sessionservice.NewRotation(repo, tokengenerate.New()).Rotate(ctx, user, hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
