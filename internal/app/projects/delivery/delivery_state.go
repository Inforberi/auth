package delivery

import (
	"slices"

	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
)

func (d *ProjectDelivery) ActiveFor(deps projectapp.ProjectSMTPDependencies) bool {
	return d != nil && d.deps == deps && d.running.Load()
}

func (d *ProjectDelivery) AllowedTargets() []string { return slices.Clone(d.cfg.SMTPAllowedTargets) }
