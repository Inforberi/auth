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

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
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
	input, err := parseCommand(args, env, diagnostics)
	if err != nil {
		return err
	}
	var codec *credentials.Codec
	if input.secrets {
		codec, err = credentials.New(env("PROVISIONER_MASTER_KEY"), env("PROVISIONER_MASTER_KEY_ID"))
		if err != nil {
			return err
		}
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
	physical, err := storage.New(conn, input.realm, input.target)
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
	preparation, err := catalog.NewPreparation(pool, input.realm, input.target)
	if err != nil {
		return err
	}
	reservation, err := preparation.Reserve(ctx, input.request)
	if err != nil {
		return err
	}
	resources, err := physical.Prepare(ctx, reservation)
	if err != nil {
		return err
	}
	stage, schemaVersion := "database_sealed", 0
	if input.schema {
		schemaVersion, err = physical.InstallSchema(ctx, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) })
		if err != nil {
			return err
		}
		stage = "schema_prepared"
	}
	if input.secrets {
		stage, err = input.prepareSecrets(ctx, physical, preparation, reservation, codec)
		if err != nil {
			return err
		}
	}
	closeStorage() // Release the target lock even if the output pipe is blocked.
	return json.NewEncoder(output).Encode(struct {
		ProjectID     domain.ID `json:"projectId"`
		Stage         string    `json:"stage"`
		DatabaseOID   uint32    `json:"databaseOid"`
		SchemaVersion int       `json:"schemaVersion,omitempty"`
	}{reservation.ProjectID, stage, resources.DatabaseOID, schemaVersion})
}

func (input command) prepareSecrets(ctx context.Context, physical *storage.Target, preparation *catalog.PreparationRepository, reservation domain.PreparationReservation, codec *credentials.Codec) (string, error) {
	binding, err := physical.SecretsBinding()
	if err != nil {
		return "", err
	}
	if err := preparation.EnsureSecrets(ctx, reservation, binding, codec); err != nil {
		return "", err
	}
	if !input.password {
		return "secrets_stored", nil
	}
	value, err := preparation.ReadDatabaseCredential(ctx, reservation, binding, codec)
	if err != nil {
		return "", err
	}
	if err := physical.InstallPassword(ctx, value, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) }); err != nil {
		return "", err
	}
	return "password_installed", nil
}

type command struct {
	request  domain.PreparationRequest
	realm    domain.ID
	target   string
	schema   bool
	secrets  bool
	password bool
}

func parseCommand(args []string, env func(string) string, diagnostics io.Writer) (command, error) {
	flags := flag.NewFlagSet("project-prepare", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	project := flags.String("project", "", "project UUID from catalog")
	operation := flags.String("operation", "", "stable begin operation UUID; reuse on retry")
	version := flags.Int64("version", 0, "expected catalog version before begin")
	generation := flags.Int64("generation", 0, "expected catalog generation before begin")
	schema := flags.Bool("schema", false, "install Auth schema and NOLOGIN runtime grants; keep database sealed")
	secrets := flags.Bool("secrets", false, "store encrypted project secrets; requires -schema; does not enable LOGIN")
	password := flags.Bool("password", false, "install saved DB password through SCRAM; requires -secrets; keep NOLOGIN")
	if err := flags.Parse(args); err != nil {
		return command{}, err
	}
	input := command{
		request: domain.PreparationRequest{ProjectID: domain.ID(*project), OperationID: domain.ID(*operation), ExpectedVersion: *version, ExpectedGeneration: *generation},
		realm:   domain.ID(env("PROVISIONER_REALM_ID")), target: env("PROVISIONER_STORAGE_TARGET"), schema: *schema, secrets: *secrets, password: *password,
	}
	if flags.NArg() != 0 || !domain.ValidID(input.request.ProjectID) || !domain.ValidID(input.request.OperationID) || *version < 1 || *generation < 1 || !domain.ValidID(input.realm) || !domain.ValidStorageTarget(input.target) {
		return command{}, errors.New("project, operation, version, generation and trusted provisioner realm/target required")
	}
	if *secrets && !*schema {
		return command{}, errors.New("-secrets requires -schema")
	}
	if *password && !*secrets {
		return command{}, errors.New("-password requires -secrets")
	}
	return input, nil
}
