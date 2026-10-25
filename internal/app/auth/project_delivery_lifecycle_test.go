package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

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

func projectDeliveryLifecycleDrill(t *testing.T, admin *pgx.Conn, cfg config.PlatformConfig, runtime *projectRuntime) {
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
			owned := &resources{}
			owned.add(func() { require.False(t, service.running.Load(), "worker must join before resources close") })
			failure := errors.New("synthetic server failure")
			app := &App{resources: owned, serve: func(ctx context.Context) error {
				return runWithDelivery(ctx, zap.NewNop(), func(ctx context.Context) error {
					require.Eventually(t, func() bool {
						var queried bool
						err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_runtime_assembly_reader' AND query LIKE '%WITH candidates AS MATERIALIZED%')`).Scan(&queried)
						return err == nil && queried && service.running.Load()
					}, 3*time.Second, 10*time.Millisecond, "worker must poll catalog without HTTP traffic")
					if mode == "serve error" {
						return failure
					}
					if mode == "context cancellation" {
						cancel()
						return ctx.Err()
					}
					return nil
				}, service)
			}}
			err := app.Run(ctx)
			switch mode {
			case "serve error":
				require.ErrorIs(t, err, failure)
			case "context cancellation":
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.NoError(t, err)
			}
			require.False(t, service.running.Load())
		})
	}
}
