package projects_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
)

func onboardingActivationFailures(t *testing.T, physical *pgx.Conn, env func(string) string, repo *preparationpostgres.PreparationRepository, r domain.PreparationReservation, b credentials.Binding, codec *credentials.Codec, runtime *pgxpool.Pool, open func() (*storage.Target, *pgx.Conn), check func(string, bool) string) {
	t.Helper()
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, strings.Replace(env("PROVISIONER_CATALOG_URL"), "auth_platform_preparation_test:catalog-fixture-only@", "auth@", 1))
	require.NoError(t, err)
	defer func() { require.NoError(t, admin.Close(ctx)) }()
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations ADD CONSTRAINT fail_activation CHECK(NOT onboarding_admitted)`)
	require.NoError(t, err)
	target, conn := open()
	require.Error(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	check("closed", false)
	require.NoError(t, conn.Close(ctx))
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations DROP CONSTRAINT fail_activation`)
	require.NoError(t, err)
	// A current catalog epoch may close an older target journal before storage generation advances.
	target, conn = open()
	require.NoError(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	require.NoError(t, conn.Close(ctx))
	next := r
	next.Version++
	next.Generation++
	next.OperationID = "b2000000-0000-4000-8000-000000000098"
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET version=$2,generation=$3 WHERE id=$1`, r.ProjectID, next.Version, next.Generation)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET version=$2,generation=$3,operation_id=$4,onboarding_admitted=false WHERE project_id=$1`, r.ProjectID, next.Version, next.Generation, next.OperationID)
	require.NoError(t, err)
	target, conn = open()
	require.ErrorIs(t, target.CloseOnboarding(ctx, r, b, repo), domain.ErrConflict)
	check("open", false)
	require.NoError(t, target.CloseOnboarding(ctx, next, b, repo))
	check("closed", false)
	require.NoError(t, conn.Close(ctx))
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET version=$2,generation=$3 WHERE id=$1`, r.ProjectID, r.Version, r.Generation)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET version=$2,generation=$3,operation_id=$4 WHERE project_id=$1`, r.ProjectID, r.Version, r.Generation, r.OperationID)
	require.NoError(t, err)
	_, err = physical.Exec(ctx, `ALTER TABLE provisioning.resources ADD CONSTRAINT fail_physical_open CHECK(onboarding_state<>'open')`)
	require.NoError(t, err)
	target, conn = open()
	require.Error(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	check("closed", false)
	require.NoError(t, conn.Close(ctx))
	_, err = physical.Exec(ctx, `ALTER TABLE provisioning.resources DROP CONSTRAINT fail_physical_open`)
	require.NoError(t, err)
	target, conn = open()
	require.NoError(t, target.ActivateOnboarding(ctx, r, b, codec, repo, runtime))
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations ADD CONSTRAINT fail_withdrawal CHECK(onboarding_admitted)`)
	require.NoError(t, err)
	require.Error(t, target.CloseOnboarding(ctx, r, b, repo))
	check("open", true) // Withdrawal must commit before any physical access is changed.
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations DROP CONSTRAINT fail_withdrawal`)
	require.NoError(t, err)
	foreignConfig := physical.Config().Copy()
	foreignConfig.Database, _, err = r.ResourceNames()
	require.NoError(t, err)
	foreign, err := pgx.ConnectConfig(ctx, foreignConfig)
	require.NoError(t, err)
	require.ErrorIs(t, target.CloseOnboarding(ctx, r, b, repo), domain.ErrConflict)
	check("closing", false)
	require.NoError(t, foreign.Ping(ctx), "must not terminate a foreign/DBA connection")
	require.NoError(t, foreign.Close(ctx))
	require.NoError(t, conn.Close(ctx))
	target, conn = open()
	require.NoError(t, target.CloseOnboarding(ctx, r, b, repo))
	check("closed", false)
	require.NoError(t, conn.Close(ctx))
	for _, failure := range []string{"executor_lost", "suspended"} {
		t.Run(failure, func(t *testing.T) {
			reached, release := make(chan struct{}), make(chan struct{})
			cfg := runtime.Config()
			cfg.BeforeConnect = func(check context.Context, _ *pgx.ConnConfig) error {
				close(reached)
				select {
				case <-release:
					if failure == "suspended" {
						return nil
					}
					return errors.New("interrupted fixture probe")
				case <-check.Done():
					return check.Err()
				}
			}
			blocked, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer blocked.Close()
			releaseProbe := sync.OnceFunc(func() { close(release) })
			defer releaseProbe()
			target, conn := open()
			finished := make(chan error, 1)
			go func() { finished <- target.ActivateOnboarding(ctx, r, b, codec, repo, blocked) }()
			select {
			case <-reached:
			case err := <-finished:
				t.Fatalf("activation failed before probe barrier: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("activation did not reach probe barrier")
			}
			check("open", false)
			if failure == "executor_lost" {
				var terminated bool
				require.NoError(t, physical.QueryRow(ctx, `SELECT pg_terminate_backend($1,1000)`, conn.PgConn().PID()).Scan(&terminated))
				require.True(t, terminated)
			} else {
				_, err := admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, r.ProjectID)
				require.NoError(t, err)
			}
			releaseProbe()
			require.Error(t, <-finished)
			require.NoError(t, conn.Close(ctx))
			if failure == "executor_lost" {
				check("open", false) // A killed maintenance session cannot pretend that cleanup succeeded.
			} else {
				check("closed", false)
			}
			target, conn = open()
			require.NoError(t, target.CloseOnboarding(ctx, r, b, repo))
			check("closed", false)
			require.NoError(t, conn.Close(ctx))
			if failure == "suspended" {
				_, err := admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, r.ProjectID, r.Version)
				require.NoError(t, err)
			}
		})
	}
}
