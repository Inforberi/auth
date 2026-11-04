package account

import (
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
)

func NewProjectUserDirectory(binding projectapp.Binding) *ProjectUserDirectory {
	return &ProjectUserDirectory{binding: binding}
}

func NewProjectUserLifecycle(binding projectapp.Binding) *ProjectUserLifecycle {
	return &ProjectUserLifecycle{binding: binding}
}
