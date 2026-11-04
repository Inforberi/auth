package domain

func (p Project) AllowsOnboarding() bool {
	return ValidID(p.ID) && ValidSlug(p.Slug) && ValidOrigin(p.Origin) &&
		p.DesiredState == Enabled && p.Phase == Provisioning && p.Version > 0 && p.Generation > 0
}
