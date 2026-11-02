package cli

import (
	"context"
	"encoding/json"
	"io"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
)

func Run(ctx context.Context, args []string, env func(string) string, output, diagnostics io.Writer) error {
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
	catalogConfig, err := preparationapp.ConnectionConfig(env("PROVISIONER_CATALOG_URL"))
	if err != nil {
		return err
	}
	storageConfig, err := preparationapp.ConnectionConfig(env("PROVISIONER_STORAGE_URL"))
	if err != nil {
		return err
	}
	result, err := preparationapp.Run(ctx, input.options(), preparationapp.Connections{Catalog: catalogConfig, Storage: storageConfig, Codec: codec})
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
