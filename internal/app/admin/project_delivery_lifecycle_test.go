package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectDeliveryDisabledAssembly(t *testing.T) {
	service, err := assembleProjectDelivery(config.PlatformConfig{}, nil, nil)
	require.NoError(t, err)
	require.Nil(t, service, "disabled must not require or build dependencies")
	service, err = assembleProjectDelivery(config.PlatformConfig{Delivery: config.ProjectDeliveryConfig{Enabled: true}}, nil, nil)
	require.Error(t, err)
	require.Nil(t, service)
}

func projectDeliveryLifecycleDrill(t *testing.T, admin *pgx.Conn, cfg config.PlatformConfig, runtime *projectapp.Runtime) {
	t.Helper()
	// The empty catalog must not dial Redis just to discover background work.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DB: 15, MaxRetries: -1})
	t.Cleanup(func() { require.NoError(t, rdb.Close()) })
	cfg.Delivery = config.ProjectDeliveryConfig{Enabled: true, Parallelism: 1, PageSize: 1, Interval: time.Second, FleetConcurrency: 1, SMTPAllowedTargets: "smtp.example.test:587"}
	service, err := assembleProjectDelivery(cfg, runtime, rdb)
	require.NoError(t, err)
	require.NotNil(t, service)
	for _, mode := range []string{"return", "serve error", "context cancellation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			owned := &authapp.Resources{}
			owned.Add(func() {
				require.False(t, service.ActiveFor(projectbinding.ProjectSMTPDependencies{Registry: runtime.Registry, Reader: runtime.Reader, Redis: rdb}), "worker must join before resources close")
			})
			failure := errors.New("synthetic server failure")
			runner := authapp.NewRuntime(nil, deploymentRetention{stopped: make(chan struct{})}, []authapp.DeliveryWorker{service}, owned, nil)
			run := func() error {
				defer owned.Close()
				return runner.Run(ctx, zap.NewNop(), func(ctx context.Context) error {
					require.Eventually(t, func() bool {
						var queried bool
						err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_runtime_assembly_reader' AND query LIKE '%WITH candidates AS MATERIALIZED%')`).Scan(&queried)
						return err == nil && queried && service.ActiveFor(projectbinding.ProjectSMTPDependencies{Registry: runtime.Registry, Reader: runtime.Reader, Redis: rdb})
					}, 3*time.Second, 10*time.Millisecond, "worker must poll catalog without HTTP traffic")
					if mode == "serve error" {
						return failure
					}
					if mode == "context cancellation" {
						cancel()
						return ctx.Err()
					}
					return nil
				})
			}
			err := run()
			switch mode {
			case "serve error":
				require.ErrorIs(t, err, failure)
			case "context cancellation":
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.NoError(t, err)
			}
			require.False(t, service.ActiveFor(projectbinding.ProjectSMTPDependencies{Registry: runtime.Registry, Reader: runtime.Reader, Redis: rdb}))
		})
	}
}
