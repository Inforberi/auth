package admin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/auth/project/delivery"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestProjectHTTPDisabledDoesNotCreateOwners(t *testing.T) {
	owned := &ownerCounter{}
	h, drain, err := openProjectHTTP(t.Context(), &config.Config{}, nil, nil, authapp.Dependencies{}, owned)
	require.NoError(t, err)
	require.Nil(t, h)
	require.Nil(t, drain)
	require.Zero(t, owned.added)
	require.Empty(t, authapp.DeliveryWorkers(nil, nil, nil, nil, (*projectdelivery.ProjectDelivery)(nil)))
}

type deploymentRetention struct{ stopped chan struct{} }

func (r deploymentRetention) RunRetention(ctx context.Context, _ func(error)) {
	<-ctx.Done()
	close(r.stopped)
}

func TestProjectHTTPDrainPrecedesWorkerJoinAndOwnedClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []string
	stopped := make(chan struct{})
	r := authapp.NewRuntime(nil, deploymentRetention{stopped: stopped}, nil, &authapp.Resources{}, func() {
		select {
		case <-stopped:
			t.Error("worker stopped before HTTP drain on serve error")
		default:
		}
		events = append(events, "http-drain")
	})
	failure := errors.New("synthetic serve error")
	err := r.Run(ctx, zap.NewNop(), func(context.Context) error { return failure })
	require.ErrorIs(t, err, failure)
	select {
	case <-stopped:
	default:
		t.Fatal("retention not joined")
	}
	owned := &authapp.Resources{}
	owned.Add(func() { events = append(events, "resources") })
	owned.Close()
	require.Equal(t, []string{"http-drain", "resources"}, events)
}

func projectHTTPDeploymentDrill(t *testing.T, runtimeConfig config.PlatformConfig, runtime *projectapp.Runtime) {
	t.Helper()
	cfg := appfixtures.OperatorConfig(runtimeConfig.RealmID)
	cfg.Platform.Runtime = runtimeConfig.Runtime
	cfg.Platform.HTTP = config.ProjectHTTPConfig{Enabled: true, MaxProfiles: 1, MaxBuilding: 1, BuildTimeout: 5 * time.Second, MaxAge: time.Minute, MaxInFlight: 1}
	appfixtures.DeploymentTokenDefaults(cfg)
	cfg.Platform.HTTP.ManifestFile = appfixtures.WriteProjectManifest(t, []byte(`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true,"google":true,"jwt":{"permissions":[{"key":"reports.read","name":"Read reports"}],"resources":[{"audience":"reports","permissions":["reports.read"]}]}}]}`))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	owned := &authapp.Resources{}
	t.Cleanup(owned.Close)
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	profile, drain, err := openProjectHTTP(t.Context(), cfg, runtime, nil, authapp.Dependencies{Redis: rdb, Logger: zap.NewNop()}, owned)
	require.NoError(t, err)
	require.NotNil(t, drain)
	server := httptest.NewTLSServer(router.ProjectHosts(cfg.Platform.Origin, operator, profile))
	t.Cleanup(server.Close)
	for host, want := range map[string]int{"console.auth.example": 204, "unknown.auth.example": 404} {
		r, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/api/v1/projects", nil)
		require.NoError(t, err)
		r.Host = host
		r.Header.Set("X-Forwarded-Host", "console.auth.example")
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, want, response.StatusCode)
	}
	drain()
	drain()
}
