package account

import (
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func NewProjectUserDirectory(binding projectbinding.Binding) *ProjectUserDirectory {
	return &ProjectUserDirectory{binding: binding}
}

func NewProjectUserLifecycle(binding projectbinding.Binding) *ProjectUserLifecycle {
	return &ProjectUserLifecycle{binding: binding}
}
