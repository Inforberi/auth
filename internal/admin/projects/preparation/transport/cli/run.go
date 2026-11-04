package cli

import (
	"context"
	"encoding/json"
	"io"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
)

// Connections contains CLI configuration only; the runner owns connection
// validation and the application resources used for preparation.
type Connections struct {
	CatalogURL, StorageURL string
	Codec                  *credentials.Codec
}

type Runner func(context.Context, preparationservice.Input, Connections) (preparationservice.Result, error)

func Run(ctx context.Context, args []string, env func(string) string, output, diagnostics io.Writer, runner Runner) error {
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
	result, err := runner(ctx, input.options(), Connections{
		CatalogURL: env("PROVISIONER_CATALOG_URL"), StorageURL: env("PROVISIONER_STORAGE_URL"), Codec: codec,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(resultResponse{ProjectID: result.ProjectID, Stage: result.Stage, DatabaseOID: result.DatabaseOID, SchemaVersion: result.SchemaVersion})
}

type resultResponse struct {
	ProjectID     domain.ID `json:"projectId"`
	Stage         string    `json:"stage"`
	DatabaseOID   uint32    `json:"databaseOid"`
	SchemaVersion int       `json:"schemaVersion,omitempty"`
}
