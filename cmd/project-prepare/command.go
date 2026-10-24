package main

import (
	"errors"
	"flag"
	"io"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type command struct {
	request    domain.PreparationRequest
	realm      domain.ID
	target     string
	schema     bool
	secrets    bool
	password   bool
	onboarding bool
	managed    bool
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
	onboarding := flags.Bool("onboarding", false, "prepare closed registration and first-admin setup; requires -password; keep sealed")
	managed := flags.Bool("managed", false, "prepare owner-managed configuration with public Auth disabled; requires -password; keep sealed")
	if err := flags.Parse(args); err != nil {
		return command{}, err
	}
	input := command{
		request: domain.PreparationRequest{ProjectID: domain.ID(*project), OperationID: domain.ID(*operation), ExpectedVersion: *version, ExpectedGeneration: *generation},
		realm:   domain.ID(env("PROVISIONER_REALM_ID")), target: env("PROVISIONER_STORAGE_TARGET"), schema: *schema, secrets: *secrets, password: *password,
	}
	input.onboarding = *onboarding
	input.managed = *managed
	if flags.NArg() != 0 || !domain.ValidID(input.request.ProjectID) || !domain.ValidID(input.request.OperationID) || *version < 1 || *generation < 1 || !domain.ValidID(input.realm) || !domain.ValidStorageTarget(input.target) {
		return command{}, errors.New("project, operation, version, generation and trusted provisioner realm/target required")
	}
	return input, input.validateStages()
}

func (input command) validateStages() error {
	if input.secrets && !input.schema {
		return errors.New("-secrets requires -schema")
	}
	if input.password && !input.secrets {
		return errors.New("-password requires -secrets")
	}
	if input.onboarding && !input.password {
		return errors.New("-onboarding requires -password")
	}
	if input.managed && !input.password {
		return errors.New("-managed requires -password")
	}
	if input.managed && input.onboarding {
		return errors.New("-managed and -onboarding are mutually exclusive")
	}
	return nil
}
