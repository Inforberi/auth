package delivery

import (
	"slices"

	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func (d *ProjectDelivery) ActiveFor(deps projectbinding.ProjectSMTPDependencies) bool {
	return d != nil && d.deps == deps && d.running.Load()
}

func (d *ProjectDelivery) AllowedTargets() []string { return slices.Clone(d.cfg.SMTPAllowedTargets) }
