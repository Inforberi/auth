package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type projectRuntime struct {
	registry *projectruntime.Registry
	reader   *projectpostgres.RuntimeCredentialReader
	realm    projectdomain.ID
}

func (r *projectRuntime) Observe(change projectdomain.TransitionReceipt) {
	r.registry.Observe(r.realm, change)
}

func openProjectRuntime(ctx context.Context, cfg config.PlatformConfig, owned *resources) (*projectRuntime, error) {
	c := cfg.Runtime
	if !c.Enabled {
		return nil, nil
	}
	target, err := projectStorageTarget(c)
	if err != nil {
		return nil, err
	}
	codec, err := credentials.New(c.MasterKey, c.MasterKeyID)
	if err != nil {
		return nil, err
	}
	connection, err := postgres.TrustedConfig(c.CatalogURL)
	if err != nil {
		return nil, err
	}
	poolCfg, err := pgxpool.ParseConfig("postgres://reader@localhost:5432/catalog?sslmode=disable")
	if err != nil {
		return nil, errors.New("project runtime reader configuration unavailable")
	}
	poolCfg.ConnConfig = connection
	poolCfg.MaxConns, poolCfg.MinConns, poolCfg.MinIdleConns = projectruntime.ReaderMaxConnections, 0, 0
	poolCfg.MaxConnLifetime, poolCfg.MaxConnIdleTime = 10*time.Minute, time.Minute
	poolCfg.HealthCheckPeriod = time.Minute
	private, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, errors.New("project runtime reader unavailable")
	}
	owned.add(private.Close)
	reader, err := projectpostgres.NewRuntimeCredentialReader(private, projectdomain.ID(cfg.RealmID), codec)
	if err != nil {
		return nil, err
	}
	if err := reader.CheckRuntime(ctx); err != nil {
		return nil, err
	}
	registry, err := projectruntime.New(c.Registry(), map[string]projectruntime.Target{cfg.StorageTarget: target}, reader, projectpostgres.CheckRuntimeConnection)
	if err != nil {
		return nil, err
	}
	// Server/workers drain first. Registry leases finish before private and shared
	// catalog pools close; this preserves known-commit completion recording.
	owned.add(func() {
		_ = registry.Close(context.WithoutCancel(ctx)) //nolint:gosec // An uncancelled final drain cannot return a context error.
	})
	if err := registry.StartSync(ctx, reader, c.SyncInterval, c.SyncTimeout); err != nil {
		return nil, err
	}
	return &projectRuntime{registry: registry, reader: reader, realm: projectdomain.ID(cfg.RealmID)}, nil
}

func projectStorageTarget(c config.ProjectRuntimeConfig) (projectruntime.Target, error) {
	if strings.HasPrefix(c.StorageHost, "/") {
		if c.StorageCAFile != "" {
			return projectruntime.Target{}, errors.New("unix socket storage cannot use PLATFORM_STORAGE_CA_FILE")
		}
		return projectruntime.NewTarget(c.StorageHost, c.StoragePort, nil)
	}
	transport := &tls.Config{ServerName: c.StorageHost, MinVersion: tls.VersionTLS12}
	if c.StorageCAFile != "" {
		cert, err := os.ReadFile(c.StorageCAFile)
		if err != nil {
			return projectruntime.Target{}, errors.New("storage CA unavailable")
		}
		transport.RootCAs = x509.NewCertPool()
		if !transport.RootCAs.AppendCertsFromPEM(cert) {
			return projectruntime.Target{}, errors.New("invalid storage CA")
		}
	}
	return projectruntime.NewTarget(c.StorageHost, c.StoragePort, transport)
}

func requireProjectCurrent(ctx context.Context, reader *projectpostgres.RuntimeCredentialReader, key projectruntime.Key) error {
	current, err := reader.CurrentRuntimes(ctx, []projectruntime.Key{key})
	if err != nil {
		return err
	}
	if !current[0] {
		return projectdomain.ErrConflict
	}
	return nil
}
