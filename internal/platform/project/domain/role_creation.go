package domain

import (
	"slices"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
)

type RoleCreation struct {
	OperationID        ID
	ProjectID          ID
	ExpectedVersion    int64
	ExpectedGeneration int64
	Key                string
	Name               string
	Description        string
	Permissions        []accessdomain.PermissionKey
	MFARequired        bool
	Reason             string
}

type RoleCreationResult struct {
	ReceiptAdmissionID ID `json:"-"`
	Role               accessdomain.Role
	Replayed           bool
	CatalogRecorded    bool
}

func (c RoleCreation) Normalize() (RoleCreation, error) {
	if !ValidID(c.OperationID) || !ValidID(c.ProjectID) || c.ExpectedVersion < 1 ||
		c.ExpectedGeneration < 1 || !validReason(c.Reason) {
		return RoleCreation{}, ErrInvalidProject
	}
	if err := accessdomain.ValidateRole(c.Key, c.Name, c.Description, c.Permissions); err != nil {
		return RoleCreation{}, err
	}
	// Permission order does not change the operation; never sort the caller's slice.
	c.Permissions = append([]accessdomain.PermissionKey{}, c.Permissions...)
	slices.Sort(c.Permissions)
	return c, nil
}
