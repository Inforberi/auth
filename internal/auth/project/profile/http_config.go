package profile

import (
	"context"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type ProjectHTTPConfig struct {
	PlatformOrigin string
	Residents      projecthttp.RuntimeDispatcherConfig
	Capacity       middleware.CapacityConfig
	Proxy          middleware.ProxyConfig
	// Also keeps existing browser sessions manageable when all login methods are disabled.
	SessionValidation *sessionservice.Config
}

type ProjectProfileSource func(context.Context, projectruntime.Key, string) (ProjectProfileConfig, error)
