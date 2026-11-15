package service

import (
	"errors"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

type Input struct {
	Request    domain.PreparationRequest
	Realm      domain.ID
	Target     string
	Schema     bool
	Secrets    bool
	Password   bool
	Onboarding bool
	Managed    bool
	Requested  bool
	Watch      bool
}

type Result struct {
	ProjectID     domain.ID
	Stage         string
	DatabaseOID   uint32
	SchemaVersion int
}

func (input Input) ValidateStages() error {
	if input.Secrets && !input.Schema {
		return errors.New("-secrets requires -schema")
	}
	if input.Password && !input.Secrets {
		return errors.New("-password requires -secrets")
	}
	if input.Onboarding && !input.Password {
		return errors.New("-onboarding requires -password")
	}
	if input.Managed && !input.Password {
		return errors.New("-managed requires -password")
	}
	if input.Managed && input.Onboarding {
		return errors.New("-managed and -onboarding are mutually exclusive")
	}
	return nil
}
