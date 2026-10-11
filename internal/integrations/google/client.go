package google

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/google/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
	oidcclient "github.com/Inforberi/financial-intelligence/internal/integrations/oidc"
)

const (
	authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	exchangeEndpoint      = "https://oauth2.googleapis.com/token"
	keysEndpoint          = "https://www.googleapis.com/oauth2/v3/certs"
)

func New(ctx context.Context, cfg service.Config) *oidcclient.Client {
	return oidcclient.New(ctx, oidcclient.Config{
		Issuer:           domain.Issuer,
		AuthorizationURL: authorizationEndpoint,
		TokenURL:         exchangeEndpoint,
		KeysURL:          keysEndpoint,
		ClientID:         cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURI: cfg.RedirectURI,
		AuthStyle: oauth2.AuthStyleInParams,
	})
}
