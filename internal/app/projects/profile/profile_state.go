package profile

import (
	"slices"
	"time"

	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type ProjectFeatureState = settingsdomain.FeatureReadiness

type ProjectReadiness struct {
	Origin        string                `json:"origin"`
	PolicyVersion int64                 `json:"policyVersion"`
	ObservedAt    time.Time             `json:"observedAt"`
	Ready         bool                  `json:"ready"`
	Features      []ProjectFeatureState `json:"features"`
}

func (p *ProjectProfile) Readiness() ProjectReadiness {
	report := ProjectReadiness{Origin: p.origin, PolicyVersion: p.policy.Version, ObservedAt: p.observedAt, Ready: p.policy.Version > 0 && !p.observedAt.IsZero(), Features: make([]ProjectFeatureState, 0, len(p.states))}
	names := make([]string, 0, len(p.states))
	for name := range p.states {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		state := p.states[name]
		report.Features = append(report.Features, state)
		if !state.Ready {
			report.Ready = false
		}
	}
	return report
}

func (p *ProjectProfile) featureReady(feature string) bool { return p.states[feature].Ready }

func (p *ProjectProfile) feature(feature string, err error) {
	reason := ""
	if err != nil {
		reason = "component_unavailable"
	}
	p.state(feature, reason)
}

func (p *ProjectProfile) state(feature, reason string) {
	p.states[feature] = ProjectFeatureState{Feature: feature, Ready: reason == "", Reason: reason}
}

func (p *ProjectProfile) deliveryReady() bool {
	d := p.deps.Delivery
	return d != nil && d.ActiveFor(projectapp.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
}
