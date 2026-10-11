package service

import (
	"context"
	"encoding/base64"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type CallbackInput struct {
	Code, State, Binding string
	UserAgent, IP        string
}

func (s *Service) Callback(ctx context.Context, input CallbackInput) (*sessionservice.CreatedSession, error) {
	ctx, cancel := flowContext(ctx)
	defer cancel()
	if !s.cfg.Enabled {
		return nil, domain.ErrDisabled
	}
	if input.Code == "" || len(input.Code) > 2048 || !validToken(input.State) || !validToken(input.Binding) {
		return nil, domain.ErrInvalidFlow
	}
	if err := s.admit(ctx, input.IP); err != nil {
		return nil, err
	}
	flow, err := s.flows.Consume(ctx, input.State, input.Binding)
	if err != nil {
		return nil, err
	}
	key, err := s.provider.Verify(ctx, input.Code, *flow)
	if err != nil {
		return nil, err
	}
	user, err := s.identities.Resolve(ctx, key, s.cfg.RegistrationEnabled)
	if err != nil {
		return nil, err
	}
	return s.sessions.CreateSessionAtVersion(ctx, user.ID, input.UserAgent, input.IP, int64(user.AuthVersion))
}

func validToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
