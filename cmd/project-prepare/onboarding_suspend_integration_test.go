package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
)

func onboardingAssemblySuspendDrill(t *testing.T, admin, project *pgxpool.Pool, observer *pgx.Conn, cfg appauth.ProjectOnboardingConfig, deps appauth.ProjectOnboardingDependencies) {
	t.Helper()
	ctx := t.Context()
	lock, err := project.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback(ctx) }()
	_, err = lock.Exec(ctx, `LOCK TABLE auth.smtp_settings IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	type result struct {
		handler http.Handler
		err     error
	}
	finished := make(chan result, 1)
	go func() {
		h, err := appauth.NewProjectOnboarding(ctx, cfg, deps)
		finished <- result{h, err}
	}()
	observe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	database, _, err := cfg.Reservation.ResourceNames()
	require.NoError(t, err)
	for {
		var waiting bool
		require.NoError(t, observer.QueryRow(observe, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE '%FROM auth.smtp_settings%')`, database).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case <-observe.Done():
			t.Fatal("assembly did not reach SMTP after first admission")
		case <-ticker.C:
		}
	}
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, cfg.Project.ID)
	require.NoError(t, err)
	require.NoError(t, lock.Rollback(ctx))
	completed := <-finished
	require.Error(t, completed.err)
	require.Nil(t, completed.handler, "late suspension must prevent returning an assembled handler")
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, cfg.Project.ID, cfg.Project.Version)
	require.NoError(t, err)
}
