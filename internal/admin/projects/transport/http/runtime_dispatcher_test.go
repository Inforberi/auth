package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type runtimeRoutesStub struct{ current func(context.Context) error }

func (s runtimeRoutesStub) CheckCurrent(ctx context.Context) error           { return s.current(ctx) }
func (s runtimeRoutesStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }

func dispatcherConfig() RuntimeDispatcherConfig {
	return RuntimeDispatcherConfig{MaxProfiles: 1, MaxBuilding: 1, BuildTimeout: time.Second, MaxAge: time.Minute}
}

func dispatcherRequest(handler http.Handler, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://"+host+"/probe", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func dispatcherBoundary(t *testing.T, dispatcher *RuntimeDispatcher) http.Handler {
	t.Helper()
	handler, err := NewRuntimeBoundary("https://admin.auth.test", runtimeResolverFunc(func(_ context.Context, origin string) (projectruntime.Key, error) {
		id := domain.ID("c7100000-0000-4000-8000-000000000002")
		if origin == "https://beta.auth.test" {
			id = "c7100000-0000-4000-8000-000000000004"
		}
		return boundaryKey(id), nil
	}), dispatcher)
	require.NoError(t, err)
	return handler
}

func TestRuntimeDispatcherReusesEvictsAndRejectsStalePolicy(t *testing.T) {
	var loads atomic.Int32
	var stale atomic.Bool
	d, err := NewRuntimeDispatcher(dispatcherConfig(), func(_ context.Context, _ projectruntime.Key, _ string) (RuntimeRoutes, error) {
		loads.Add(1)
		return runtimeRoutesStub{current: func(context.Context) error {
			if stale.Load() {
				return settingsdomain.ErrPolicyConflict
			}
			return nil
		}}, nil
	})
	require.NoError(t, err)
	h := dispatcherBoundary(t, d)
	require.Equal(t, 204, dispatcherRequest(h, "alpha.auth.test").Code)
	require.Equal(t, 204, dispatcherRequest(h, "alpha.auth.test").Code)
	require.EqualValues(t, 1, loads.Load())
	require.Equal(t, 204, dispatcherRequest(h, "beta.auth.test").Code)
	require.Equal(t, 204, dispatcherRequest(h, "alpha.auth.test").Code)
	require.EqualValues(t, 3, loads.Load())
	stale.Store(true)
	require.Equal(t, 404, dispatcherRequest(h, "alpha.auth.test").Code)
	stale.Store(false)
	require.Equal(t, 204, dispatcherRequest(h, "alpha.auth.test").Code)
	require.EqualValues(t, 4, loads.Load())
	d.mu.Lock()
	d.entries["https://alpha.auth.test"].created = time.Now().Add(-2 * time.Minute)
	d.mu.Unlock()
	require.Equal(t, 204, dispatcherRequest(h, "alpha.auth.test").Code)
	require.EqualValues(t, 5, loads.Load())
	require.NoError(t, d.Close(context.Background()))
	require.Equal(t, 503, dispatcherRequest(h, "alpha.auth.test").Code)
	// Missing boundary selection cannot choose a cached project.
	require.Equal(t, 503, dispatcherRequest(d, "alpha.auth.test").Code)
}

func TestRuntimeDispatcherBoundsColdBuildAndDrains(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	d, err := NewRuntimeDispatcher(dispatcherConfig(), func(ctx context.Context, _ projectruntime.Key, _ string) (RuntimeRoutes, error) {
		close(started)
		select {
		case <-release:
			return runtimeRoutesStub{current: func(context.Context) error { return nil }}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	require.NoError(t, err)
	h := dispatcherBoundary(t, d)
	done := make(chan int, 1)
	go func() { done <- dispatcherRequest(h, "alpha.auth.test").Code }()
	<-started
	require.Equal(t, 503, dispatcherRequest(h, "alpha.auth.test").Code)
	require.Equal(t, 503, dispatcherRequest(h, "beta.auth.test").Code)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	require.ErrorIs(t, d.Close(ctx), context.DeadlineExceeded)
	close(release)
	require.Equal(t, 503, <-done)
	require.NoError(t, d.Close(context.Background()))
	require.Empty(t, d.entries)
}

func TestRuntimeDispatcherBuildCancellationDoesNotPoisonEntry(t *testing.T) {
	d, err := NewRuntimeDispatcher(dispatcherConfig(), func(ctx context.Context, _ projectruntime.Key, _ string) (RuntimeRoutes, error) {
		return nil, ctx.Err()
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = d.get(ctx, RuntimeSelection{key: boundaryKey("c7100000-0000-4000-8000-000000000002"), origin: "https://alpha.auth.test"})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, d.entries)
	require.Zero(t, d.building)
}
