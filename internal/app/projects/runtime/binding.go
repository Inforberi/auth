package runtime

import (
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
)

// Binding borrows one project generation; adapters retain its existing lease/authority checks.
type Binding struct {
	Key      projectruntime.Key
	Registry *projectruntime.Registry
	Reader   *runtimepostgres.RuntimeCredentialReader
}
