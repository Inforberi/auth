package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
)

type StartedFlow struct {
	URL     string
	Binding string
}

func (s *Service) Start(ctx context.Context, ip string) (*StartedFlow, error) {
	ctx, cancel := flowContext(ctx)
	defer cancel()
	if err := s.admit(ctx, ip); err != nil {
		return nil, err
	}
	return s.startFlow(ctx, domain.Flow{Purpose: domain.Login})
}

func (s *Service) startFlow(ctx context.Context, flow domain.Flow) (*StartedFlow, error) {
	parts := make([]string, 4)
	for i := range parts {
		var err error
		parts[i], err = s.tokens.GenerateToken()
		if err != nil {
			return nil, err
		}
	}
	state, binding := parts[0], parts[1]
	flow.Verifier, flow.Nonce = parts[2], parts[3]
	if err := s.flows.Save(ctx, state, binding, flow); err != nil {
		return nil, err
	}
	return &StartedFlow{URL: s.provider.AuthorizationURL(state, flow), Binding: binding}, nil
}
