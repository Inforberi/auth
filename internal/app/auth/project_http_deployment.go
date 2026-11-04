package auth

import (
	"context"
	"errors"
	"net/http"

	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/app/projects/browser"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/app/projects/delivery"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func openProjectHTTP(ctx context.Context, cfg *config.Config, runtime *projectapp.Runtime, delivery *projectdelivery.ProjectDelivery, deps Dependencies, owned *Resources) (*projectbrowser.ProjectHTTP, func(), error) {
	c := cfg.Platform.HTTP
	if !c.Enabled {
		return nil, nil, nil
	}
	if runtime == nil {
		return nil, nil, errors.New("project HTTP requires runtime")
	}

	if err := cfg.ValidatePlatform(); err != nil {
		return nil, nil, err
	}
	deployment, err := projectprofile.LoadProjectAuthDeployment(cfg)
	if err != nil {
		return nil, nil, err
	}
	dependencies := projectprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: runtime.Registry, Reader: runtime.Reader, Redis: deps.Redis, Hash: deps.Hash}, Delivery: delivery}
	if deployment.NeedsBotAPI() {
		botClient, openErr := telegrambot.New(ctx, 8)
		err = openErr
		dependencies.BotAPI = botClient
		if err != nil {
			return nil, nil, err
		}
		owned.Add(botClient.Close)
	}
	if deployment.NeedsOIDC() {
		dependencies.OIDCClients = projectmethods.NewProjectOIDCClients(ctx)
		owned.Add(dependencies.OIDCClients.Close)
	}
	if deployment.NeedsTokenRedis() {
		dependencies.IssuanceRedis, err = projectnative.NewProjectTokenRedis(deps.Redis)
		if err != nil {
			return nil, nil, err
		}
		owned.Add(func() {
			if err := dependencies.IssuanceRedis.Close(); err != nil {
				deps.Logger.Error("project token Redis close failed")
			}
		})
	}
	profile, err := projectbrowser.NewProjectHTTP(projectprofile.ProjectHTTPConfig{
		PlatformOrigin: cfg.Platform.Origin,
		Residents:      projecthttp.RuntimeDispatcherConfig{MaxProfiles: c.MaxProfiles, MaxBuilding: c.MaxBuilding, BuildTimeout: c.BuildTimeout, MaxAge: c.MaxAge},
		Capacity:       middleware.CapacityConfig{MaxInFlight: c.MaxInFlight, RequestTimeout: cfg.HTTP.RequestTimeout}, Proxy: cfg.Proxy,
		SessionValidation: &cfg.Session,
	}, dependencies, deployment.Profile, deps.Logger)
	if err != nil {
		return nil, nil, err
	}
	drain := func() {
		if err := profile.Close(context.WithoutCancel(ctx)); err != nil {
			deps.Logger.Error("project HTTP drain failed")
		}
	}
	owned.Add(drain)
	return profile, drain, nil
}

func projectHostRouter(platformOrigin string, operator http.Handler, project *projectbrowser.ProjectHTTP) http.Handler {
	if project == nil {
		return operator
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "https://"+r.Host == platformOrigin {
			operator.ServeHTTP(w, r)
			return
		}
		project.ServeHTTP(w, r)
	})
}
