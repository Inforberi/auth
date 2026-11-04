package runtime

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
)

func RequireCurrent(ctx context.Context, reader *runtimepostgres.RuntimeCredentialReader, key projectruntime.Key) error {
	current, err := reader.CurrentRuntimes(ctx, []projectruntime.Key{key})
	if err != nil {
		return err
	}
	if !current[0] {
		return projectdomain.ErrConflict
	}
	return nil
}
