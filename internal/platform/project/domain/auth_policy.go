package domain

import (
	"strings"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type AuthPolicyUpdate struct {
	OperationID                         ID
	ProjectID                           ID
	ExpectedVersion, ExpectedGeneration int64
	ExpectedPolicyVersion               int64
	Policy                              settingsdomain.Policy
	Reason                              string
}

func (c AuthPolicyUpdate) Normalize() (AuthPolicyUpdate, error) {
	c.Reason = strings.TrimSpace(c.Reason)
	if !ValidID(c.OperationID) || !ValidID(c.ProjectID) || c.ExpectedVersion < 1 || c.ExpectedGeneration < 1 || c.ExpectedPolicyVersion < 1 || !validReason(c.Reason) {
		return c, ErrInvalidProject
	}
	return c, c.Policy.Validate()
}

type AuthPolicyResult struct {
	Snapshot           settingsdomain.Snapshot
	Changed, Replayed  bool
	ReceiptAdmissionID ID
}

type AuthPolicyOutcome struct {
	OperationID ID
	Committed   bool
	AuthPolicyResult
}
