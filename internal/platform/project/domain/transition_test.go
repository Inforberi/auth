package domain

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestProjectTransitionMatrix(t *testing.T) {
	type edge struct {
		state  DesiredState
		phase  Phase
		action Action
	}
	allowed := map[edge]struct {
		state DesiredState
		phase Phase
	}{
		{Enabled, Pending, BeginPreparation}:         {Enabled, Provisioning},
		{Enabled, Provisioning, FailPreparation}:     {Enabled, Failed},
		{Suspended, Provisioning, FailPreparation}:   {Suspended, Failed},
		{Enabled, Provisioning, FinishPreparation}:   {Enabled, Ready},
		{Suspended, Provisioning, FinishPreparation}: {Suspended, Ready},
		{Enabled, Failed, RetryPreparation}:          {Enabled, Pending},
	}
	for _, phase := range []Phase{Pending, Provisioning, Failed, Ready} {
		allowed[edge{Enabled, phase, Suspend}] = struct {
			state DesiredState
			phase Phase
		}{Suspended, phase}
		allowed[edge{Suspended, phase, Resume}] = struct {
			state DesiredState
			phase Phase
		}{Enabled, phase}
	}
	for _, state := range []DesiredState{Enabled, Suspended, "", "unknown"} {
		for _, phase := range []Phase{Pending, Provisioning, Failed, Ready, "", "unknown"} {
			for _, action := range []Action{BeginPreparation, FailPreparation, FinishPreparation, RetryPreparation, Suspend, Resume, "health_timeout", ""} {
				p := Project{ID: "1c82c477-3a57-4823-8c49-a476550d8a21", Slug: "shop", Name: "Shop", Origin: "https://shop.auth.example", DesiredState: state, Phase: phase, Version: 7, Generation: 3}
				before := p
				next, err := p.Next(action)
				want, ok := allowed[edge{state, phase, action}]
				if ok {
					if err != nil || next.DesiredState != want.state || next.Phase != want.phase || next.Version != 8 || next.Generation != 4 ||
						next.ID != p.ID || next.Slug != p.Slug || next.Name != p.Name || next.Origin != p.Origin {
						t.Fatalf("incorrect transition %v/%v/%v: %+v %v", state, phase, action, next, err)
					}
				} else if !errors.Is(err, ErrInvalidTransition) {
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
	base := Transition{ProjectID: "1c82c477-3a57-4823-8c49-a476550d8a21", OperationID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222", ActorKind: OperatorActor, Action: Suspend, ExpectedVersion: 1, ExpectedGeneration: 1, Reason: "INC-42"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Transition){
		func(c *Transition) { c.ProjectID = "invalid" },
		func(c *Transition) { c.OperationID = "" },
		func(c *Transition) { c.ActorID = "00000000-0000-0000-0000-000000000000" },
		func(c *Transition) { c.ExpectedVersion = 0 },
		func(c *Transition) { c.ExpectedGeneration = 0 },
		func(c *Transition) { c.ActorKind = ProvisionerActor },
		func(c *Transition) { c.Action = BeginPreparation },
		func(c *Transition) { c.Action = "health_timeout" },
	} {
		invalid := base
		mutate(&invalid)
		if !errors.Is(invalid.Validate(), ErrInvalidProject) {
			t.Fatal("invalid command accepted")
		}
	}
	for _, reason := range []string{"", " padded ", "line\n", "hidden\u0085", string([]byte{255}), strings.Repeat("я", 251)} {
		invalid := base
		invalid.Reason = reason
		if !errors.Is(invalid.Validate(), ErrInvalidProject) {
			t.Fatal("unsafe or unbounded reason accepted")
		}
	}
	for _, action := range []Action{BeginPreparation, FailPreparation, FinishPreparation} {
		c := base
		c.Action, c.ActorKind = action, ProvisionerActor
		if err := c.Validate(); err != nil {
			t.Fatal("provisioner action rejected", err)
		}
	}
	for _, p := range []Project{
		{DesiredState: Enabled, Phase: Ready, Version: math.MaxInt64, Generation: 1},
		{DesiredState: Enabled, Phase: Ready, Version: 1, Generation: math.MaxInt64},
		{DesiredState: Enabled, Phase: Ready},
	} {
		if _, err := p.Next(Suspend); !errors.Is(err, ErrConflict) {
			t.Fatal("counter overflow or invalid version accepted", err)
		}
	}
}
