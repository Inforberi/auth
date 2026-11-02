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

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectHTTPDisabledDoesNotCreateOwners(t *testing.T) {
	owned := &resources{}
	h, drain, err := openProjectHTTP(t.Context(), &config.Config{}, nil, nil, realmDependencies{}, owned)
	require.NoError(t, err)
	require.Nil(t, h)
	require.Nil(t, drain)
	require.Empty(t, owned.closers)
	require.Empty(t, realmDeliveryWorkers(nil, nil, nil, nil, (*ProjectDelivery)(nil)))
}

func TestProjectHostRoutingHasNoOperatorFallback(t *testing.T) {
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) })
	project := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	h := projectHostRouter("https://platform.example.test", operator, &ProjectHTTP{Handler: project})
	for host, want := range map[string]int{"platform.example.test": 201, "project.example.test": 404, "Platform.example.test": 404, "platform.example.test.attacker.test": 404} {
		r := httptest.NewRequest("GET", "https://"+host+"/api/v1/projects", nil)
		r.Header.Set("X-Forwarded-Host", "platform.example.test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, want, w.Code)
	}
}

func TestProjectDeploymentSourceIsImmutableAndUsesProjectURLs(t *testing.T) {
	cfg := &config.Config{}
	cfg.Platform.Delivery.Enabled = true
	cfg.Platform.HTTP.BuildTimeout = 5 * time.Second
	cfg.Account.EncryptionKey = "synthetic-platform-secret"
	cfg.Account.URL, cfg.Password.ResetURL = "https://platform.example.test/verify", "https://platform.example.test/reset"
	cfg.Google.ClientSecret = "synthetic-provider-secret"
	cfg.JWT.Enabled = true
	source := projectBrowserDeployment(cfg)
	cfg.Platform.Delivery.Enabled = false
	a, err := source(context.Background(), projectruntime.Key{}, "https://alpha.example.test")
	require.NoError(t, err)
	b, err := source(context.Background(), projectruntime.Key{}, "https://beta.example.test")
	require.NoError(t, err)
	require.Equal(t, "https://alpha.example.test/verify-email", a.Verification.URL)
	require.Equal(t, "https://beta.example.test/reset-password", b.Recovery.ResetURL)
	require.Empty(t, a.Verification.EncryptionKey)
	require.Nil(t, a.Google)
	require.Nil(t, a.Tokens)
	a.Password.Session.SessionTTL = time.Second
	require.NotEqual(t, a.Password.Session.SessionTTL, b.Password.Session.SessionTTL)
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
	r := &realm{retention: deploymentRetention{stopped: stopped}, drainHTTP: func() {
		select {
		case <-stopped:
			t.Error("worker stopped before HTTP drain on serve error")
		default:
		}
		events = append(events, "http-drain")
	}}
	failure := errors.New("synthetic serve error")
	err := r.run(ctx, zap.NewNop(), func(context.Context) error { return failure })
	require.ErrorIs(t, err, failure)
	select {
	case <-stopped:
	default:
		t.Fatal("retention not joined")
	}
	owned := &resources{}
	owned.add(func() { events = append(events, "resources") })
	owned.close()
	require.Equal(t, []string{"http-drain", "resources"}, events)
}

func projectHTTPDeploymentDrill(t *testing.T, runtimeConfig config.PlatformConfig, runtime *projectRuntime) {
	t.Helper()
	cfg := operatorConfig(runtimeConfig.RealmID)
	cfg.Platform.Runtime = runtimeConfig.Runtime
	cfg.Platform.HTTP = config.ProjectHTTPConfig{Enabled: true, MaxProfiles: 1, MaxBuilding: 1, BuildTimeout: 5 * time.Second, MaxAge: time.Minute, MaxInFlight: 1}
	deploymentTokenDefaults(cfg)
	cfg.Platform.HTTP.ManifestFile = writeProjectManifest(t, []byte(`{"version":1,"projects":[{"id":"c2000000-0000-4000-8000-000000000002","browser":true,"google":true,"jwt":{"permissions":[{"key":"reports.read","name":"Read reports"}],"resources":[{"audience":"reports","permissions":["reports.read"]}]}}]}`))
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	owned := &resources{}
	t.Cleanup(owned.close)
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	profile, drain, err := openProjectHTTP(t.Context(), cfg, runtime, nil, realmDependencies{redis: rdb, log: zap.NewNop()}, owned)
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
