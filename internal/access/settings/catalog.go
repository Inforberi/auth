package settings

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

type Permission struct {
	Key         domain.PermissionKey `json:"key"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Group       string               `json:"group,omitempty"`
}

const (
	RolesManage        domain.PermissionKey = "access.roles.manage"
	AssignmentsManage  domain.PermissionKey = "access.assignments.manage"
	EmailBindingManage domain.PermissionKey = "accounts.email.bind"
	UsersManage        domain.PermissionKey = "accounts.users.manage"
	UsersRead          domain.PermissionKey = "accounts.users.read"
	UsersStatusManage  domain.PermissionKey = "accounts.users.status.manage"
	UsersDelete        domain.PermissionKey = "accounts.users.delete"
)

type Catalog struct {
	permissions map[domain.PermissionKey]Permission
}

func NewCatalog(permissions []Permission) (Catalog, error) {
	if len(permissions) > 505 {
		return Catalog{}, domain.ErrInvalidPermission
	}
	c := Catalog{permissions: map[domain.PermissionKey]Permission{
		RolesManage:        {Key: RolesManage, Name: "Manage roles", Group: "Access"},
		AssignmentsManage:  {Key: AssignmentsManage, Name: "Assign and revoke roles", Group: "Access"},
		EmailBindingManage: {Key: EmailBindingManage, Name: "Approve initial email binding", Group: "Accounts"},
		UsersManage:        {Key: UsersManage, Name: "Create users and issue activation credentials", Group: "Accounts"},
		UsersRead:          {Key: UsersRead, Name: "View users and authentication configuration", Group: "Accounts"},
		UsersStatusManage:  {Key: UsersStatusManage, Name: "Block and unblock users", Group: "Accounts"},
		UsersDelete:        {Key: UsersDelete, Name: "Delete user accounts", Group: "Accounts"},
	}}
	for _, permission := range permissions {
		if !domain.ValidKey(string(permission.Key)) || !utf8.ValidString(permission.Name) ||
			strings.TrimSpace(permission.Name) == "" || len(permission.Name) > 200 ||
			!utf8.ValidString(permission.Description) || len(permission.Description) > 2000 ||
			!utf8.ValidString(permission.Group) || len(permission.Group) > 200 {
			return Catalog{}, domain.ErrInvalidPermission
		}
		if _, exists := c.permissions[permission.Key]; exists {
			return Catalog{}, fmt.Errorf("%w: duplicate key %s", domain.ErrInvalidPermission, permission.Key)
		}
		c.permissions[permission.Key] = permission
	}
	return c, nil
}

func (c Catalog) Contains(key domain.PermissionKey) bool {
	_, exists := c.permissions[key]
	return exists
}

func (c Catalog) Permissions() []Permission {
	result := make([]Permission, 0, len(c.permissions))
	for _, permission := range c.permissions {
		result = append(result, permission)
	}
	slices.SortFunc(result, func(a, b Permission) int { return strings.Compare(string(a.Key), string(b.Key)) })
	return result
}
