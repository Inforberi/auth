package settings

import (
	"errors"
	"slices"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

const (
	FormatVersion    = 1
	MaxCatalogBytes  = 256 * 1024
	MaxRoleTemplates = 64
)

var ErrInvalidCatalog = errors.New("invalid access catalog")

type Definition struct {
	Version       int            `json:"version"`
	Permissions   []Permission   `json:"permissions"`
	RoleTemplates []RoleTemplate `json:"roleTemplates,omitempty"`
}

type RoleTemplate struct {
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Permissions []domain.PermissionKey `json:"permissions"`
}

type Document struct {
	definition Definition
	catalog    Catalog
}

func NewDocument(definition Definition) (Document, error) {
	definition.Permissions = slices.Clone(definition.Permissions)
	definition.RoleTemplates = definition.Templates()
	catalog, err := definition.Catalog()
	if err != nil {
		return Document{}, err
	}
	return Document{definition: definition, catalog: catalog}, nil
}

func (d Document) Catalog() Catalog          { return d.catalog }
func (d Document) Templates() []RoleTemplate { return d.definition.Templates() }

func (d Definition) Catalog() (Catalog, error) {
	if d.Version != FormatVersion || len(d.RoleTemplates) > MaxRoleTemplates {
		return Catalog{}, ErrInvalidCatalog
	}
	catalog, err := NewCatalog(d.Permissions)
	if err != nil {
		return Catalog{}, err
	}
	seen := make(map[string]struct{}, len(d.RoleTemplates))
	for _, role := range d.RoleTemplates {
		if err := domain.ValidateRole(role.Key, role.Name, role.Description, role.Permissions); err != nil {
			return Catalog{}, err
		}
		if _, duplicate := seen[role.Key]; duplicate {
			return Catalog{}, ErrInvalidCatalog
		}
		seen[role.Key] = struct{}{}
		for _, key := range role.Permissions {
			if !catalog.Contains(key) {
				return Catalog{}, domain.ErrInvalidPermission
			}
		}
	}
	return catalog, nil
}

func (d Definition) Templates() []RoleTemplate {
	result := slices.Clone(d.RoleTemplates)
	for i := range result {
		result[i].Permissions = slices.Clone(result[i].Permissions)
	}
	return result
}
