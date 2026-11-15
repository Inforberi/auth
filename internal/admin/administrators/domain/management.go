package domain

import (
	"errors"
	"slices"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

var (
	ErrInvalidManagement = errors.New("invalid operator management command")
	ErrOperatorConflict  = errors.New("operator management conflict")
	ErrOwnerProtected    = errors.New("platform owner is protected")
)

type Management struct {
	OperationID, UserID accountdomain.UserID
	Action              string
	Permissions         []Permission
	Email               string
}

func (m Management) Validate() (Management, error) {
	if !accountdomain.ValidUserID(m.OperationID) || len(m.Permissions) > 5 {
		return Management{}, ErrInvalidManagement
	}
	switch m.Action {
	case "invite":
		if m.UserID != "" || m.Email == "" || len(m.Permissions) == 0 {
			return Management{}, ErrInvalidManagement
		}
	case "permissions", "revoke":
		if !accountdomain.ValidUserID(m.UserID) || m.Email != "" || (m.Action == "revoke") != (len(m.Permissions) == 0) {
			return Management{}, ErrInvalidManagement
		}
	default:
		return Management{}, ErrInvalidManagement
	}
	m.Permissions = append([]Permission{}, m.Permissions...)
	slices.Sort(m.Permissions)
	for i, permission := range m.Permissions {
		if !permission.Valid() || permission == OperatorsManage || (i > 0 && m.Permissions[i-1] == permission) {
			return Management{}, ErrInvalidManagement
		}
	}
	return m, nil
}

type Operator struct {
	UserID      accountdomain.UserID `json:"userId" swaggertype:"string"`
	Email       string               `json:"email"`
	Status      accountdomain.Status `json:"status" swaggertype:"string"`
	Permissions []Permission         `json:"permissions" swaggertype:"array,string"`
	Owner       bool                 `json:"owner"`
}
