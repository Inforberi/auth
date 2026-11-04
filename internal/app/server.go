package app

import (
	"context"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/app/auth"
	"github.com/Inforberi/financial-intelligence/internal/server/http"
)

func newApplication(assembled *auth.Runtime, owned *auth.Resources, log *zap.Logger, cfg httpserver.Config) *App {
	return &App{
		Access: assembled.Access, Provisioning: assembled.Provisioning, TemporaryPasswords: assembled.TemporaryPasswords,
		resources: owned,
		serve: func(ctx context.Context) error {
			return assembled.Run(ctx, log, func(ctx context.Context) error {
				return httpserver.Run(ctx, log, cfg, assembled.Handler)
			})
		},
	}
}
