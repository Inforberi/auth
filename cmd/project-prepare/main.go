package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/platform/project/storage/postgres"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	cancel()
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, env func(string) string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("project-prepare", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	project := flags.String("project", "", "project UUID from catalog")
	operation := flags.String("operation", "", "stable begin operation UUID; reuse on retry")
	version := flags.Int64("version", 0, "expected catalog version before begin")
	generation := flags.Int64("generation", 0, "expected catalog generation before begin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	realm := domain.ID(env("PROVISIONER_REALM_ID"))
	target := env("PROVISIONER_STORAGE_TARGET")
	if flags.NArg() != 0 || !domain.ValidID(domain.ID(*project)) || !domain.ValidID(domain.ID(*operation)) || *version < 1 || *generation < 1 || !domain.ValidID(realm) || !domain.ValidStorageTarget(target) {
		return errors.New("project, operation, version, generation and trusted provisioner realm/target required")
	}
	catalogConfig, err := connectionConfig(env("PROVISIONER_CATALOG_URL"))
	if err != nil {
		return err
	}
	storageConfig, err := connectionConfig(env("PROVISIONER_STORAGE_URL"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, storageConfig)
	if err != nil {
		return errors.New("storage connection failed")
	}
	closeStorage := func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(cleanup) //nolint:gosec // A dedicated connection is never returned to a pool with a held lock.
	}
	defer closeStorage()
	physical, err := storage.New(conn, realm, target)
	if err != nil {
		return err
	}
	if err := physical.CheckRuntime(ctx); err != nil {
		return err
	}
	poolConfig, err := pgxpool.ParseConfig(env("PROVISIONER_CATALOG_URL"))
	if err != nil {
		return errors.New("catalog configuration failed")
	}
	poolConfig.ConnConfig = catalogConfig
	poolConfig.MaxConns, poolConfig.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("catalog connection failed")
	}
	defer pool.Close()
	preparation, err := catalog.NewPreparation(pool, realm, target)
	if err != nil {
		return err
	}
	reservation, err := preparation.Reserve(ctx, domain.PreparationRequest{
		ProjectID: domain.ID(*project), OperationID: domain.ID(*operation), ExpectedVersion: *version, ExpectedGeneration: *generation,
	})
	if err != nil {
		return err
	}
	resources, err := physical.Prepare(ctx, reservation)
	if err != nil {
		return err
	}
	closeStorage() // Release the target lock even if the output pipe is blocked.
	return json.NewEncoder(output).Encode(struct {
		ProjectID   domain.ID `json:"projectId"`
		Stage       string    `json:"stage"`
		DatabaseOID uint32    `json:"databaseOid"`
	}{reservation.ProjectID, "database_sealed", resources.DatabaseOID})
}
