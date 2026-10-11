package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type CallbackInput struct {
	Code, State, Binding string
	UserAgent, IP        string
	SessionToken         string `json:"-"`
}

type CallbackResult struct {
	Session *sessionservice.CreatedSession
	Linked  bool
}

func (s *Service) Callback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
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
	if flow.Purpose != domain.Login && flow.Purpose != domain.Link {
		return nil, domain.ErrInvalidFlow
	}
	if flow.Purpose == domain.Link {
		if input.SessionToken == "" || len(input.SessionToken) > 128 ||
			subtle.ConstantTimeCompare([]byte(flow.SessionHash), []byte(s.tokens.Hash(input.SessionToken))) != 1 {
			return nil, accountdomain.ErrFreshAuthRequired
		}
	}
	key, err := s.provider.Verify(ctx, input.Code, *flow)
	if err != nil {
		return nil, err
	}
	if flow.Purpose == domain.Link {
		if err := s.management.Link(ctx, flow.UserID, flow.SessionHash, key); err != nil {
			return nil, err
		}
		return &CallbackResult{Linked: true}, nil
	}
	user, err := s.identities.Resolve(ctx, key, s.cfg.RegistrationEnabled)
	if err != nil {
		return nil, err
	}
	session, err := s.sessions.CreateSessionAtVersion(ctx, user.ID, input.UserAgent, input.IP, int64(user.AuthVersion))
	if err != nil {
		return nil, err
	}
	return &CallbackResult{Session: session}, nil
}

func validToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
