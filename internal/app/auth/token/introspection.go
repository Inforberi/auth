package token

import (
	"github.com/jackc/pgx/v5/pgxpool"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/introspection/transport/http"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func assembleIntrospection(pool *pgxpool.Pool, limiter service.IntrospectionLimiter, public []byte, cfg settings.Config, resources []service.Resource, catalog accesssettings.Catalog) (*tokenintrospectionhttp.IntrospectionHandler, error) {
	if cfg.IntrospectionClientFile == "" {
		return nil, nil
	}
	clients, err := settings.LoadIntrospectionClients(cfg.IntrospectionClientFile)
	if err != nil {
		return nil, err
	}
	keys, err := authjwt.ParsePublicKeys(public)
	if err != nil {
		return nil, err
	}
	svc, err := service.NewIntrospection(tokenpostgres.New(pool), limiter, keys, service.IntrospectionConfig{
		Issuer: cfg.Issuer, Resources: resources, Clients: clients,
		ConsumerPerMinute: cfg.IntrospectionConsumerPerMinute, ProjectPerMinute: cfg.IntrospectionProjectPerMinute,
	}, catalog)
	if err != nil {
		return nil, err
	}
	return tokenintrospectionhttp.NewIntrospection(svc), nil
}
