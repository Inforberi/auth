package domain

import (
	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type RoleAssignment struct {
	OperationID           ID
	ProjectID             ID
	ExpectedVersion       int64
	ExpectedGeneration    int64
	Action                RoleAction
	UserID                accountdomain.UserID
	RoleID                accessdomain.RoleID
	ExpectedRoleVersion   int64
	ExpectedAccessVersion int64
	Reason                string
}

type RoleAssignmentSnapshot struct {
	Action        RoleAction
	UserID        accountdomain.UserID
	Role          accessdomain.Role
	AccessVersion int64
	Changed       bool
}

type RoleAssignmentResult struct {
	ReceiptAdmissionID ID `json:"-"`
	RoleAssignmentSnapshot
	Replayed        bool
	CatalogRecorded bool
}

func (c RoleAssignment) Normalize() (RoleAssignment, error) {
	if !ValidID(c.OperationID) || !ValidID(c.ProjectID) || c.ExpectedVersion < 1 || c.ExpectedGeneration < 1 || !validReason(c.Reason) {
		return RoleAssignment{}, ErrInvalidProject
	}
	if (c.Action != RoleGrant && c.Action != RoleRevoke) || !accountdomain.ValidUserID(c.UserID) || !ValidID(ID(c.RoleID)) || c.ExpectedRoleVersion < 1 || c.ExpectedAccessVersion < 1 {
		return RoleAssignment{}, accessdomain.ErrInvalidRole
	}
	return c, nil
}
