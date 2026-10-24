package domain

import (
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

var (
	ErrAdmissionExpired   = errors.New("role operation admission expired")
	ErrRoleOutcomeUnknown = errors.New("role operation outcome unknown")
)

type RoleAction string

const (
	RoleCreate RoleAction = "create"
	RoleGrant  RoleAction = "grant"
	RoleRevoke RoleAction = "revoke"
)

// RoleIntent records preparation, not project mutation or an authority ticket.
type RoleIntent struct {
	OperationID ID
	CreatedAt   time.Time
	Replayed    bool
}

// Committed is evidence about the original operation, not current access.
// False remains unknown, never proof that the project mutation rolled back.
type RoleOutcome struct {
	OperationID   ID
	ProjectID     ID
	Action        RoleAction
	Committed     bool
	Role          accessdomain.Role
	UserID        accountdomain.UserID
	AccessVersion int64
	Changed       bool
}
