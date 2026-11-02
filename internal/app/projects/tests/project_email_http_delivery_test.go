package projects_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
)

func runEmailHTTPDelivery(t *testing.T, f *emailIsolationFixture) *appauth.ProjectDelivery {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	allowed := []string{f.listeners[0].Addr().String(), f.listeners[1].Addr().String()}
	deps := appauth.ProjectSMTPDependencies{Registry: f.projects.deps.Registry, Reader: f.projects.deps.Reader, Redis: f.projects.deps.Redis}
	runner, err := appauth.NewProjectDelivery(appauth.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Minute, SMTPAllowedTargets: allowed}, deps)
	require.NoError(t, err)
	var probes []<-chan error
	for _, listener := range f.listeners {
		tcp, ok := listener.(*net.TCPListener)
		require.True(t, ok)
		done := make(chan error, 1)
		probes = append(probes, done)
		go func() { done <- emailHTTPProbe(ctx, tcp) }()
	}
	finished := make(chan error, 1)
	go func() { finished <- runner.Run(ctx, func(error) {}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(7 * time.Second):
			t.Error("email HTTP delivery did not drain")
		}
		for _, done := range probes {
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(7 * time.Second):
				t.Error("email HTTP SMTP probe did not drain")
			}
		}
	})
	return runner
}

func emailHTTPProbe(ctx context.Context, listener *net.TCPListener) error {
	released := make(chan struct{})
	close(released)
	for ctx.Err() == nil {
		if err := listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return err
		}
		done := make(chan error, 1)
		projectSMTPGreeting(ctx, listener, make(chan struct{}), released, done)
		err := <-done
		if ctx.Err() != nil {
			return nil
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}
