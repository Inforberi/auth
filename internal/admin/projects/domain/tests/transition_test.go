package domain_test

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func TestProjectTransitionMatrix(t *testing.T) {
	type edge struct {
		state  domain.DesiredState
		phase  domain.Phase
		action domain.Action
	}
	allowed := map[edge]struct {
		state domain.DesiredState
		phase domain.Phase
	}{
		{domain.Enabled, domain.Pending, domain.BeginPreparation}:         {domain.Enabled, domain.Provisioning},
		{domain.Enabled, domain.Provisioning, domain.FailPreparation}:     {domain.Enabled, domain.Failed},
		{domain.Suspended, domain.Provisioning, domain.FailPreparation}:   {domain.Suspended, domain.Failed},
		{domain.Enabled, domain.Provisioning, domain.FinishPreparation}:   {domain.Enabled, domain.Ready},
		{domain.Suspended, domain.Provisioning, domain.FinishPreparation}: {domain.Suspended, domain.Ready},
		{domain.Enabled, domain.Failed, domain.RetryPreparation}:          {domain.Enabled, domain.Pending},
	}
	for _, phase := range []domain.Phase{domain.Pending, domain.Provisioning, domain.Failed, domain.Ready} {
		allowed[edge{domain.Enabled, phase, domain.Suspend}] = struct {
			state domain.DesiredState
			phase domain.Phase
		}{domain.Suspended, phase}
		allowed[edge{domain.Suspended, phase, domain.Resume}] = struct {
			state domain.DesiredState
			phase domain.Phase
		}{domain.Enabled, phase}
	}
	for _, state := range []domain.DesiredState{domain.Enabled, domain.Suspended, "", "unknown"} {
		for _, phase := range []domain.Phase{domain.Pending, domain.Provisioning, domain.Failed, domain.Ready, "", "unknown"} {
			for _, action := range []domain.Action{domain.BeginPreparation, domain.FailPreparation, domain.FinishPreparation, domain.RetryPreparation, domain.Suspend, domain.Resume, "health_timeout", ""} {
				p := domain.Project{ID: "1c82c477-3a57-4823-8c49-a476550d8a21", Slug: "shop", Name: "Shop", Origin: "https://shop.auth.example", DesiredState: state, Phase: phase, Version: 7, Generation: 3}
				before := p
				next, err := p.Next(action)
				want, ok := allowed[edge{state, phase, action}]
				if ok {
					if err != nil || next.DesiredState != want.state || next.Phase != want.phase || next.Version != 8 || next.Generation != 4 ||
						next.ID != p.ID || next.Slug != p.Slug || next.Name != p.Name || next.Origin != p.Origin {
						t.Fatalf("incorrect transition %v/%v/%v: %+v %v", state, phase, action, next, err)
					}
				} else if !errors.Is(err, domain.ErrInvalidTransition) {
					t.Fatalf("invalid edge accepted %v/%v/%v: %v", state, phase, action, err)
				}
				if p != before {
					t.Fatal("transition mutated the original snapshot")
				}
			}
		}
	}
}

func TestTransitionBounds(t *testing.T) {
	base := domain.Transition{ProjectID: "1c82c477-3a57-4823-8c49-a476550d8a21", OperationID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222", ActorKind: domain.OperatorActor, Action: domain.Suspend, ExpectedVersion: 1, ExpectedGeneration: 1, Reason: "INC-42"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*domain.Transition){
		func(c *domain.Transition) { c.ProjectID = "invalid" },
		func(c *domain.Transition) { c.OperationID = "" },
		func(c *domain.Transition) { c.ActorID = "00000000-0000-0000-0000-000000000000" },
		func(c *domain.Transition) { c.ExpectedVersion = 0 },
		func(c *domain.Transition) { c.ExpectedGeneration = 0 },
		func(c *domain.Transition) { c.ActorKind = domain.ProvisionerActor },
		func(c *domain.Transition) { c.Action = domain.BeginPreparation },
		func(c *domain.Transition) { c.Action = "health_timeout" },
	} {
		invalid := base
		mutate(&invalid)
		if !errors.Is(invalid.Validate(), domain.ErrInvalidProject) {
			t.Fatal("invalid command accepted")
		}
	}
	for _, reason := range []string{"", " padded ", "line\n", "hidden\u0085", string([]byte{255}), strings.Repeat("я", 251)} {
		invalid := base
		invalid.Reason = reason
		if !errors.Is(invalid.Validate(), domain.ErrInvalidProject) {
			t.Fatal("unsafe or unbounded reason accepted")
		}
	}
	for _, action := range []domain.Action{domain.BeginPreparation, domain.FailPreparation, domain.FinishPreparation} {
		c := base
		c.Action, c.ActorKind = action, domain.ProvisionerActor
		if err := c.Validate(); err != nil {
			t.Fatal("provisioner action rejected", err)
		}
	}
	for _, p := range []domain.Project{
		{DesiredState: domain.Enabled, Phase: domain.Ready, Version: math.MaxInt64, Generation: 1},
		{DesiredState: domain.Enabled, Phase: domain.Ready, Version: 1, Generation: math.MaxInt64},
		{DesiredState: domain.Enabled, Phase: domain.Ready},
	} {
		if _, err := p.Next(domain.Suspend); !errors.Is(err, domain.ErrConflict) {
			t.Fatal("counter overflow or invalid version accepted", err)
		}
	}
}
