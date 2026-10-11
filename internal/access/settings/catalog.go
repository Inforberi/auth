package settings

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

type Permission struct {
	Key domain.PermissionKey
	Name string
}

type Catalog struct {
	permissions map[domain.PermissionKey]Permission
}

func NewCatalog(permissions []Permission) (Catalog, error) {
	if len(permissions) == 0 || len(permissions) > 512 {
		return Catalog{}, domain.ErrInvalidPermission
	}
	c := Catalog{permissions: make(map[domain.PermissionKey]Permission, len(permissions))}
	for _, permission := range permissions {
		if !domain.ValidKey(string(permission.Key)) || !utf8.ValidString(permission.Name) ||
			strings.TrimSpace(permission.Name) == "" || len(permission.Name) > 200 {
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
