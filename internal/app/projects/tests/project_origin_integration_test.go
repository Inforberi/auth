package projects_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
)

func projectOriginHTTPDrill(t *testing.T, admin *pgx.Conn, reader *runtimepostgres.RuntimeCredentialReader, registry *projectruntime.Registry, key projectruntime.Key, origin string) {
	t.Helper()
	ctx := t.Context()
	resolved, err := reader.ResolveRuntime(ctx, origin)
	require.NoError(t, err)
	require.Equal(t, key, resolved)
	unknown, err := reader.ResolveRuntime(ctx, "https://missing-boundary.example.test")
	require.ErrorIs(t, err, domain.ErrNotFound)
	require.Equal(t, projectruntime.Key{}, unknown)
	_, err = reader.ResolveRuntime(ctx, strings.ToUpper(origin))
	require.ErrorIs(t, err, domain.ErrInvalidProject)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = reader.ResolveRuntime(canceled, origin)
	require.Error(t, err)
	parsed, err := url.Parse(origin)
	require.NoError(t, err)
	var calls atomic.Int64
	handler, err := projecthttp.NewRuntimeBoundary("https://admin.boundary.example.test", reader, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selected, ok := projecthttp.RuntimeFromContext(r.Context())
		if !ok || selected.Key() != key || selected.Origin() != origin {
			t.Error("mixed project request context")
			http.Error(w, "unavailable", 500)
			return
		}
		calls.Add(1)
		err := registry.UsePool(r.Context(), selected.Key(), func(ctx context.Context, pool *pgxpool.Pool) error {
			var actual string
			if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&actual); err != nil {
				return err
			}
			if actual != "authp_"+strings.ReplaceAll(string(key.Binding.ProjectID), "-", "") {
				t.Error("wrong project database")
			}
			return nil
		})
		if err != nil {
			t.Errorf("selected runtime probe: %v", err)
			http.Error(w, "unavailable", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	t.Cleanup(client.CloseIdleConnections)
	request := func(host, requestOrigin string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/probe", nil)
		require.NoError(t, err)
		req.Host = host
		req.Header.Set("X-Forwarded-Host", parsed.Host)
		req.Header.Set("X-Project-ID", "f8700000-0000-4000-8000-000000000001")
		if requestOrigin != "" {
			req.Header.Set("Origin", requestOrigin)
		}
		response, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, want, response.StatusCode)
		require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
	}
	request(parsed.Host, origin, 204)
	require.Equal(t, int64(1), calls.Load())
	request("missing-boundary.example.test", "", 404)
	request("admin.boundary.example.test", "", 404)
	request(parsed.Host, "https://foreign-boundary.example.test", 403)
	require.Equal(t, int64(1), calls.Load())
	// The helper performs a fresh catalog selection for each request; it never caches admission.
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_, err := admin.Exec(cleanup, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, key.Binding.ProjectID)
		require.NoError(t, err)
	})
	request(parsed.Host, origin, 404)
	require.Equal(t, int64(1), calls.Load())
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	request(parsed.Host, origin, 204)
	require.Equal(t, int64(2), calls.Load())
}
