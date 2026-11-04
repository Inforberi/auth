package profile

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (s *projectHTTPSessions) bindHandlers(handlers map[string]http.HandlerFunc, log *zap.Logger) {
	h := sessionhttp.NewHandler(s, log)
	handlers["/api/v1/auth/me"], handlers["/api/v1/auth/sessions"] = h.Me, h.List
	handlers["/api/v1/auth/logout"], handlers["/api/v1/auth/logout-all"] = h.Logout, h.LogoutAll
	handlers["/api/v1/auth/sessions/{id}"] = func(w http.ResponseWriter, r *http.Request) {
		h.Revoke(w, r, chi.URLParam(r, "id"))
	}
	handlers["/api/v1/auth/session/activity"] = sessionhttp.NewActivity(s, log).Record
	handlers["/api/v1/auth/session/rotate"] = sessionhttp.NewRotation(s, log).Rotate
}

func (s *projectHTTPSessions) List(ctx context.Context, user accountdomain.UserID, hash, before string) (*sessionservice.SessionPage, error) {
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

func (s *projectHTTPSessions) Revoke(ctx context.Context, user accountdomain.UserID, hash, id string) error {
	return s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		return sessionservice.NewManagement(repo).Revoke(ctx, user, hash, id)
	})
}

func (s *projectHTTPSessions) LogoutAll(ctx context.Context, user accountdomain.UserID, hash string) error {
	return s.use(ctx, func(ctx context.Context, repo *sessionpostgres.Repository) error {
		return sessionservice.NewManagement(repo).LogoutAll(ctx, user, hash)
	})
}

func (s *projectHTTPSessions) Record(ctx context.Context, user accountdomain.UserID, hash string) (*sessionservice.ActivityResult, error) {
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

func (s *projectHTTPSessions) Rotate(ctx context.Context, user accountdomain.UserID, hash string) (*sessionservice.CreatedSession, error) {
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
