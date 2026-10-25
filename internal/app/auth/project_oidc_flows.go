package auth

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	oidcservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/service"
)

func (p *ProjectOIDC) Start(ctx context.Context, ip string) (*oidcservice.StartedFlow, error) {
	var result *oidcservice.StartedFlow
	err := p.use(ctx, func(ctx context.Context, service *oidcservice.Service) error {
		var err error
		result, err = service.Start(ctx, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectOIDC) Callback(ctx context.Context, input oidcservice.CallbackInput) (*oidcservice.CallbackResult, error) {
	var result *oidcservice.CallbackResult
	err := p.use(ctx, func(ctx context.Context, service *oidcservice.Service) error {
		var err error
		result, err = service.Callback(ctx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectOIDC) StartLink(ctx context.Context, user accountdomain.UserID, sessionHash, ip string) (*oidcservice.StartedFlow, error) {
	var result *oidcservice.StartedFlow
	err := p.use(ctx, func(ctx context.Context, service *oidcservice.Service) error {
		var err error
		result, err = service.StartLink(ctx, user, sessionHash, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *ProjectOIDC) Unlink(ctx context.Context, user accountdomain.UserID, sessionHash, ip string) error {
	return p.use(ctx, func(ctx context.Context, service *oidcservice.Service) error {
		return service.Unlink(ctx, user, sessionHash, ip)
	})
}
