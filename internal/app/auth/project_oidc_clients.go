package auth

import (
	"context"

	googleservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
	telegramservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	googleclient "github.com/Inforberi/financial-intelligence/internal/integrations/google"
	oidcclient "github.com/Inforberi/financial-intelligence/internal/integrations/oidc"
	telegramclient "github.com/Inforberi/financial-intelligence/internal/integrations/telegram"
)

// ProjectOIDCClients owns process-wide transports and key caches; close after project operations drain.
type ProjectOIDCClients struct {
	google, telegram *oidcclient.Client
}

func NewProjectOIDCClients(ctx context.Context) *ProjectOIDCClients {
	return &ProjectOIDCClients{google: googleclient.New(ctx, googleservice.Config{}), telegram: telegramclient.New(ctx, telegramservice.Config{})}
}

func (c *ProjectOIDCClients) Close() { c.google.Close(); c.telegram.Close() }

func (c *ProjectOIDCClients) client(name string) *oidcclient.Client {
	if c == nil {
		return nil
	}
	switch name {
	case "google":
		return c.google
	case "telegram":
		return c.telegram
	default:
		return nil
	}
}
