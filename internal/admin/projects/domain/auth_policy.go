package domain

import (
	"strings"
	"time"

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
	Readiness          *AuthPolicyReadiness
}

type AuthPolicyReadiness struct {
	Runtime       settingsdomain.PolicyRuntime
	Tokens        settingsdomain.TokenDeployment
	Features      []settingsdomain.FeatureReadiness
	ObservedAt    time.Time
	PolicyVersion int64
}

func (r AuthPolicyReadiness) MFAReady() bool {
	for _, feature := range r.Features {
		if feature.Feature == "mfa_management" {
			return feature.Ready
		}
	}
	return false
}

type AuthPolicyView struct {
	Snapshot  settingsdomain.Snapshot
	Readiness AuthPolicyReadiness
}

type AuthPolicyOutcome struct {
	OperationID ID
	Committed   bool
	AuthPolicyResult
}
