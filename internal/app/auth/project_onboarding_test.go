package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func TestProjectOnboardingValidationBeforeSQL(t *testing.T) {
	codec, err := credentials.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	b := credentials.Binding{
		RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: "a2000000-0000-4000-8000-000000000001",
		ReservationID: "b2000000-0000-4000-8000-000000000001", StorageTarget: "primary",
		DatabaseOID: 100, OwnerOID: 101, RuntimeOID: 102, SchemaVersion: 1,
	}
	payload, err := codec.Generate(b)
	require.NoError(t, err)
	keys, err := codec.OpenOnboarding(b, credentials.Version, "root-1", payload)
	require.NoError(t, err)
	for _, mode := range []string{"project", "slug", "origin", "state", "phase", "version", "generation", "keys", "catalog", "reservation", "pool", "redis", "logger", "hasher", "http", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			cfg := ProjectOnboardingConfig{
				Project: projectdomain.Project{
					ID: b.ProjectID, Slug: "test-project", Origin: "https://project.example.test",
					DesiredState: projectdomain.Enabled, Phase: projectdomain.Provisioning, Version: 1, Generation: 1,
				},
				Keys: keys, HTTP: requestmiddleware.CapacityConfig{MaxInFlight: 2, RequestTimeout: time.Second},
				Reservation: projectdomain.PreparationReservation{
					ProjectID: b.ProjectID, ReservationID: b.ReservationID,
					OperationID: "b2000000-0000-4000-8000-000000000002", StorageTarget: b.StorageTarget, Version: 1, Generation: 1,
				},
			}
			deps := ProjectOnboardingDependencies{
				Pool: &pgxpool.Pool{}, Redis: &redis.Client{}, Logger: zap.NewNop(),
				Hash: hasher.NewBounded(&blockingHash{}, 1), Catalog: &pgxpool.Pool{},
			}
			switch mode {
			case "project":
				cfg.Project.ID = "a2000000-0000-4000-8000-000000000002"
			case "slug":
				cfg.Project.Slug = ""
			case "origin":
				cfg.Project.Origin = "http://project.example.test"
			case "state":
				cfg.Project.DesiredState = projectdomain.Suspended
			case "phase":
				cfg.Project.Phase = projectdomain.Ready
			case "version":
				cfg.Project.Version = 0
			case "generation":
				cfg.Project.Generation = 0
			case "keys":
				cfg.Keys = credentials.OnboardingKeys{}
			case "catalog":
				deps.Catalog = nil
			case "reservation":
				cfg.Reservation.OperationID = ""
			case "pool":
				deps.Pool = nil
			case "redis":
				deps.Redis = nil
			case "logger":
				deps.Logger = nil
			case "hasher":
				deps.Hash = nil
			case "http":
				cfg.HTTP.MaxInFlight = 0
			case "proxy":
				cfg.Proxy.TrustedCIDRs = []string{"invalid"}
			}
			handler, err := NewProjectOnboarding(t.Context(), cfg, deps)
			require.Error(t, err)
			require.Nil(t, handler)
		})
	}
}
