package domain

import (
	"slices"
	"time"

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

// RoleCreationIntent records preparation, not a project mutation or an authority ticket.
type RoleCreationIntent struct {
	OperationID ID
	CreatedAt   time.Time
	Replayed    bool
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
