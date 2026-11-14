package domain

import "errors"

var ErrInvalidLoginBudget = errors.New("invalid login budget policy")

type LoginBudgetPolicy struct {
	IPPerMinute                 int `json:"ipPerMinute"`
	IdentityPerMinute           int `json:"identityPerMinute"`
	GlobalPerMinute             int `json:"globalPerMinute"`
	RegistrationIPPerMinute     int `json:"registrationIpPerMinute"`
	RegistrationGlobalPerMinute int `json:"registrationGlobalPerMinute"`
	ResetGlobalPerMinute        int `json:"resetGlobalPerMinute"`
}

func (p LoginBudgetPolicy) Validate(ceiling LoginBudgetPolicy) error {
	if p.IPPerMinute < 1 || p.IPPerMinute > ceiling.IPPerMinute ||
		p.IdentityPerMinute < 1 || p.IdentityPerMinute > ceiling.IdentityPerMinute ||
		p.GlobalPerMinute < 1 || p.GlobalPerMinute > ceiling.GlobalPerMinute ||
		p.RegistrationIPPerMinute < 1 || p.RegistrationIPPerMinute > ceiling.RegistrationIPPerMinute ||
		p.RegistrationGlobalPerMinute < 1 || p.RegistrationGlobalPerMinute > ceiling.RegistrationGlobalPerMinute ||
		p.ResetGlobalPerMinute < 1 || p.ResetGlobalPerMinute > ceiling.ResetGlobalPerMinute {
		return ErrInvalidLoginBudget
	}
	return nil
}
