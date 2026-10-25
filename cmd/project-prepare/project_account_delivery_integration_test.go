package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func (f projectAccountFixture) delivery(t *testing.T, ctx context.Context, invited, bound, changed accountdomain.UserID) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	runner, err := appauth.NewProjectDelivery(appauth.ProjectDeliveryConfig{Parallelism: 1, PageSize: projectruntime.StateBatchSize, Interval: time.Second, SMTPAllowedTargets: []string{f.listener.Addr().String()}}, f.deps)
	require.NoError(t, err)
	release := make(chan struct{})
	close(release)
	networkDone := make(chan struct{})
	failures := make(chan error, 3)
	go func() {
		defer close(networkDone)
		for range 3 {
			result := make(chan error, 1)
			projectSMTPGreeting(ctx, f.listener, make(chan struct{}), release, result)
			failures <- <-result
		}
	}()
	reports := make(chan error, projectruntime.StateBatchSize)
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = runner.Run(ctx, func(err error) {
			select {
			case reports <- err:
			case <-ctx.Done():
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, f.listener.Close())
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("account delivery runner did not drain")
		}
		select {
		case <-networkDone:
		case <-time.After(6 * time.Second):
			t.Error("account SMTP fixture did not drain")
		}
	})
	timeout := time.NewTimer(25 * time.Second)
	defer timeout.Stop()
	ready := false
	for !ready {
		select {
		case <-reports:
			require.NoError(t, f.db.QueryRow(ctx, `SELECT
    EXISTS(SELECT 1 FROM auth.invitation_outbox o JOIN auth.account_invitations i USING(digest) WHERE i.user_id=$1 AND o.attempts>0 AND o.lease IS NULL)
    AND EXISTS(SELECT 1 FROM auth.email_bindings WHERE user_id=$2 AND delivery_attempts>0 AND lease IS NULL)
    AND EXISTS(SELECT 1 FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$3 AND o.attempts>0 AND o.lease IS NULL)`, invited, bound, changed).Scan(&ready))
		case <-timeout.C:
			t.Fatal("invitation/binding/change queues did not each get delivery opportunity")
		}
	}
	cancel()
	<-done
	require.ErrorIs(t, runErr, context.Canceled)
	<-networkDone
	for range 3 {
		require.NoError(t, <-failures)
	}
}
