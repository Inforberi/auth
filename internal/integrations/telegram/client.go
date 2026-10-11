package telegram

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	oidcclient "github.com/Inforberi/financial-intelligence/internal/integrations/oidc"
)

const Issuer = domain.Issuer

func New(ctx context.Context, cfg service.Config) *oidcclient.Client {
	return oidcclient.New(ctx, oidcclient.Config{
		Issuer: Issuer, AuthorizationURL: Issuer + "/auth", TokenURL: Issuer + "/token", KeysURL: Issuer + "/.well-known/jwks.json",
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURI: cfg.RedirectURI, AuthStyle: oauth2.AuthStyleInHeader,
	})
}
