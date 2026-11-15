package projects_test

import (
	"context"

	preparationservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
	preparationapp "github.com/Inforberi/financial-intelligence/internal/app/projects/preparation"
)

func runPreparationCommand(ctx context.Context, input preparationservice.Input, connections preparationcli.Connections) (preparationservice.Result, error) {
	catalog, err := preparationapp.ConnectionConfig(connections.CatalogURL)
	if err != nil {
		return preparationservice.Result{}, err
	}
	storage, err := preparationapp.ConnectionConfig(connections.StorageURL)
	if err != nil {
		return preparationservice.Result{}, err
	}
	configured := preparationapp.Connections{Catalog: catalog, Storage: storage, Codec: connections.Codec}
	if input.Watch {
		return preparationapp.Watch(ctx, input, configured)
	}
	return preparationapp.Run(ctx, input, configured)
}
