package auth

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

	projectbrowser "github.com/Inforberi/financial-intelligence/internal/app/projects/browser"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/app/projects/delivery"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	appfixtures "github.com/Inforberi/financial-intelligence/internal/app/tests/fixtures"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectHTTPDisabledDoesNotCreateOwners(t *testing.T) {
	owned := &Resources{}
	h, drain, err := openProjectHTTP(t.Context(), &config.Config{}, nil, nil, Dependencies{}, owned)
	require.NoError(t, err)
	require.Nil(t, h)
	require.Nil(t, drain)
	require.Empty(t, owned.closers)
	require.Empty(t, realmDeliveryWorkers(nil, nil, nil, nil, (*projectdelivery.ProjectDelivery)(nil)))
}

func TestProjectHostRoutingHasNoOperatorFallback(t *testing.T) {
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) })
	project := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	h := projectHostRouter("https://platform.example.test", operator, &projectbrowser.ProjectHTTP{Handler: project})
	for host, want := range map[string]int{"platform.example.test": 201, "project.example.test": 404, "Platform.example.test": 404, "platform.example.test.attacker.test": 404} {
		r := httptest.NewRequest("GET", "https://"+host+"/api/v1/projects", nil)
		r.Header.Set("X-Forwarded-Host", "platform.example.test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, want, w.Code)
	}
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
	r := &Runtime{retention: deploymentRetention{stopped: stopped}, drainHTTP: func() {
		select {
		case <-stopped:
			t.Error("worker stopped before HTTP drain on serve error")
		default:
		}
		events = append(events, "http-drain")
	}}
	failure := errors.New("synthetic serve error")
	err := r.Run(ctx, zap.NewNop(), func(context.Context) error { return failure })
	require.ErrorIs(t, err, failure)
	select {
	case <-stopped:
	default:
		t.Fatal("retention not joined")
	}
	owned := &Resources{}
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
	owned := &Resources{}
	t.Cleanup(owned.Close)
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	profile, drain, err := openProjectHTTP(t.Context(), cfg, runtime, nil, Dependencies{Redis: rdb, Logger: zap.NewNop()}, owned)
	require.NoError(t, err)
	require.NotNil(t, drain)
	server := httptest.NewTLSServer(projectHostRouter(cfg.Platform.Origin, operator, profile))
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
