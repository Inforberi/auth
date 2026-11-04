package profile

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
)

func TestFactoryMissingDependenciesReturnsNilInterface(t *testing.T) {
	source := runtimeprofile.ProjectProfileSource(func(_ context.Context, _ projectruntime.Key, _ string) (runtimeprofile.ProjectProfileConfig, error) {
		t.Fatal("incomplete factory must not call deployment source")
		return runtimeprofile.ProjectProfileConfig{}, nil
	})
	for _, deps := range []runtimeprofile.ProjectProfileDependencies{
		{},
		{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: &projectruntime.Registry{}}},
		{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Reader: &projectpostgres.RuntimeCredentialReader{}}},
	} {
		require.True(t, NewFactory(deps, source) == nil, "interface must be nil, not contain a typed nil factory")
	}
	require.True(t, NewFactory(runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: &projectruntime.Registry{}, Reader: &projectpostgres.RuntimeCredentialReader{}}}, nil) == nil)
}
