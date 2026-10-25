package http

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type runtimeResolverFunc func(context.Context, string) (projectruntime.Key, error)

func (f runtimeResolverFunc) ResolveRuntime(ctx context.Context, origin string) (projectruntime.Key, error) {
	return f(ctx, origin)
}

func boundaryKey(id domain.ID) projectruntime.Key {
	return projectruntime.Key{Version: 1, Generation: 1, Binding: credentials.Binding{RealmID: "c7100000-0000-4000-8000-000000000001", ProjectID: id, ReservationID: "c7100000-0000-4000-8000-000000000003", StorageTarget: "primary", DatabaseOID: 1, OwnerOID: 2, RuntimeOID: 3, SchemaVersion: 1}}
}

func TestRuntimeBoundaryAuthorityAndErrors(t *testing.T) {
	key := boundaryKey("c7100000-0000-4000-8000-000000000002")
	for _, test := range []struct {
		name, host, origin, url string
		plain, opaque           bool
		err                     error
		invalidKey              bool
		want                    int
	}{
		{name: "valid", host: "alpha.auth.test", want: 204},
		{name: "same origin", host: "alpha.auth.test", origin: "https://alpha.auth.test", want: 204},
		{name: "plaintext", host: "alpha.auth.test", plain: true, want: 404},
		{name: "platform", host: "admin.auth.test", want: 404},
		{name: "unknown", host: "unknown.auth.test", err: domain.ErrNotFound, want: 404},
		{name: "malformed", host: "Alpha.auth.test", err: domain.ErrInvalidProject, want: 404},
		{name: "foreign origin", host: "alpha.auth.test", origin: "https://beta.auth.test", want: 403},
		{name: "absolute mismatch", host: "alpha.auth.test", url: "https://beta.auth.test/probe", want: 404},
		{name: "opaque target", host: "alpha.auth.test", opaque: true, want: 404},
		{name: "absolute plaintext", host: "alpha.auth.test", url: "http://alpha.auth.test/probe", want: 404},
		{name: "unavailable", host: "alpha.auth.test", err: domain.ErrUnavailable, want: 503},
		{name: "bad key", host: "alpha.auth.test", invalidKey: true, want: 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			reached := false
			resolver := runtimeResolverFunc(func(_ context.Context, origin string) (projectruntime.Key, error) {
				require.Equal(t, "https://"+test.host, origin)
				if test.invalidKey {
					return projectruntime.Key{}, nil
				}
				return key, test.err
			})
			handler, err := NewRuntimeBoundary("https://admin.auth.test", resolver, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				selected, ok := RuntimeFromContext(r.Context())
				require.True(t, ok)
				require.Equal(t, key, selected.Key())
				require.Equal(t, "https://"+test.host, selected.Origin())
				w.WriteHeader(204)
			}))
			require.NoError(t, err)
			target := test.url
			if target == "" {
				target = "/probe"
			}
			request := httptest.NewRequest("GET", target, nil)
			if test.opaque {
				request.URL.Scheme = "https"
				request.URL.Opaque = "//beta.auth.test/probe"
				request.URL.Host = ""
			}
			request.Host = test.host
			request.TLS = &tls.ConnectionState{}
			if test.plain {
				request.TLS = nil
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			request.Header.Set("X-Forwarded-Host", "beta.auth.test")
			request.Header.Set("X-Project-ID", "c7100000-0000-4000-8000-000000000099")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, test.want, response.Code)
			require.Equal(t, test.want == 204, reached)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestRuntimeBoundaryLookupCancellationDoesNotCancelHandler(t *testing.T) {
	key := boundaryKey("c7100000-0000-4000-8000-000000000002")
	parent, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var lookup context.Context
	resolver := runtimeResolverFunc(func(ctx context.Context, _ string) (projectruntime.Key, error) {
		lookup = ctx
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), 3*time.Second)
		return key, nil
	})
	handler, err := NewRuntimeBoundary("https://admin.auth.test", resolver, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.ErrorIs(t, lookup.Err(), context.Canceled)
		require.NoError(t, r.Context().Err())
		deadline, ok := r.Context().Deadline()
		require.True(t, ok)
		require.Greater(t, time.Until(deadline), 30*time.Second)
		w.WriteHeader(204)
	}))
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(parent, "GET", "/probe", nil)
	request.Host = "alpha.auth.test"
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, 204, response.Code)
}

func TestRuntimeSelectionIsRequestLocal(t *testing.T) {
	keys := map[string]projectruntime.Key{"https://alpha.auth.test": boundaryKey("c7100000-0000-4000-8000-000000000002"), "https://beta.auth.test": boundaryKey("c7100000-0000-4000-8000-000000000004")}
	handler, err := NewRuntimeBoundary("https://admin.auth.test", runtimeResolverFunc(func(_ context.Context, origin string) (projectruntime.Key, error) { return keys[origin], nil }), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selected, ok := RuntimeFromContext(r.Context())
		if !ok || selected.Key() != keys["https://"+r.Host] {
			t.Error("mixed project context")
		}
		w.WriteHeader(204)
	}))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			host := "alpha.auth.test"
			if i%2 == 1 {
				host = "beta.auth.test"
			}
			request := httptest.NewRequest("GET", "/probe", nil)
			request.Host = host
			request.TLS = &tls.ConnectionState{}
			handler.ServeHTTP(httptest.NewRecorder(), request)
		})
	}
	wg.Wait()
}
