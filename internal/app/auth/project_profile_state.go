package auth

import (
	"slices"
	"time"
)

type ProjectFeatureState struct {
	Feature string `json:"feature"`
	Ready   bool   `json:"ready"`
	Reason  string `json:"reason,omitempty"`
}

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
	return d != nil && d.deps.Registry == p.deps.Registry && d.deps.Reader == p.deps.Reader && d.deps.Redis == p.deps.Redis && d.running.Load()
}
