package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
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
	if key.Issuer != s.cfg.Issuer {
		return nil, domain.ErrInvalidFlow
	}
	if flow.Purpose == domain.Link {
		if err := s.management.Link(ctx, flow.UserID, flow.SessionHash, key); err != nil {
			return nil, err
		}
		return &CallbackResult{Linked: true}, nil
	}
	user, err := s.identities.Resolve(ctx, key, s.registrationAllowed())
	if err != nil {
		return nil, err
	}
	session, err := s.sessions.BeginLogin(ctx, mfaservice.PrimaryProof{
		UserID: user.ID, AuthVersion: int64(user.AuthVersion),
		Method: "oidc", Issuer: key.Issuer, Reference: key.Subject, VerifiedAt: time.Now().UTC(),
	}, input.UserAgent, input.IP)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{Session: session}, nil
}

func (s *Service) registrationAllowed() bool {
	// SQL owns the live registration flag when a persisted policy is connected.
	return s.cfg.CheckPolicy != nil || s.cfg.RegistrationEnabled
}

func validToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
