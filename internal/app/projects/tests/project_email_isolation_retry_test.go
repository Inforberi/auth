package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectdelivery "github.com/Inforberi/financial-intelligence/internal/app/projects/delivery"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
)

func checkEmailIsolationRetries(t *testing.T, ctx context.Context, f *emailIsolationFixture) {
	t.Helper()
	runCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	allowed := []string{f.listeners[0].Addr().String(), f.listeners[1].Addr().String()}
	deps := projectapp.ProjectSMTPDependencies{Registry: f.projects.deps.Registry, Reader: f.projects.deps.Reader, Redis: f.projects.deps.Redis}
	runner, err := projectdelivery.NewProjectDelivery(projectdelivery.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Second, SMTPAllowedTargets: allowed}, deps)
	require.NoError(t, err)
	released := make(chan struct{})
	close(released)
	for _, listener := range f.listeners {
		for range 2 {
			done := make(chan error, 1)
			go projectSMTPGreeting(runCtx, listener, make(chan struct{}), released, done)
			t.Cleanup(func() {
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(6 * time.Second):
					t.Error("SMTP isolation probe did not drain")
				}
			})
		}
	}
	reported := make(chan error, projectruntime.StateBatchSize)
	finished := make(chan error, 1)
	go func() {
		finished <- runner.Run(runCtx, func(err error) {
			select {
			case reported <- err:
			default:
			}
		})
	}()
	joined := false
	stop := func() {
		cancel()
		if joined {
			return
		}
		select {
		case err := <-finished:
			joined = true
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Error("two-project delivery did not drain")
		}
	}
	t.Cleanup(stop)
	defer stop()
	for {
		select {
		case <-reported:
			ready := true
			for _, db := range f.projects.databases {
				var retried bool
				require.NoError(t, db.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM auth.email_verification_outbox WHERE attempts=1 AND lease IS NULL AND available_at>clock_timestamp())
 AND EXISTS(SELECT 1 FROM auth.password_reset_outbox WHERE attempts=1 AND lease IS NULL AND available_at>clock_timestamp())`).Scan(&retried))
				ready = ready && retried
			}
			if ready {
				return
			}
		case <-runCtx.Done():
			t.Fatal("both project queues must independently schedule a retry")
		}
	}
}
