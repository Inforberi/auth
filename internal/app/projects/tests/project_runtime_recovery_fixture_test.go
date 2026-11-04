package projects_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

func serveRecoveryProjects(t *testing.T, f projectIsolationHTTP) ([2]isolationHTTP, *projectbrowser.ProjectHTTP) {
	t.Helper()
	h, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test",
		Residents:      projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute},
		Capacity:       middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &f.password.Session,
	}, f.deps, func(_ context.Context, key projectruntime.Key, origin string) (runtimeprofile.ProjectProfileConfig, error) {
		for i, expected := range f.projects {
			// Revisions change on resume; the project binding and its origin stay independent.
			if key.Binding == expected.Binding && origin == f.origins[i] {
				return runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, Timeout: 5 * time.Second}, nil
			}
		}
		return runtimeprofile.ProjectProfileConfig{}, projectdomain.ErrConflict
	}, nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(h)
	server.Client().Timeout = 10 * time.Second
	t.Cleanup(func() {
		server.Close()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		require.NoError(t, h.Close(ctx))
	})
	return [2]isolationHTTP{{server: server, origin: f.origins[0]}, {server: server, origin: f.origins[1]}}, h
}

type isolationLifecycleObserver struct {
	realm    projectdomain.ID
	registry *projectruntime.Registry
}

func (o isolationLifecycleObserver) Observe(receipt projectdomain.TransitionReceipt) {
	o.registry.Observe(o.realm, receipt)
}
