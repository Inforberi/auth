package settings

import (
	"slices"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

type Changes struct {
	AddedPermissions   []domain.PermissionKey `json:"addedPermissions"`
	RemovedPermissions []domain.PermissionKey `json:"removedPermissions"`
	ChangedPermissions []domain.PermissionKey `json:"changedPermissions"`
	AddedTemplates     []string               `json:"addedTemplates"`
	RemovedTemplates   []string               `json:"removedTemplates"`
	ChangedTemplates   []string               `json:"changedTemplates"`
}

func Preview(current, candidate Document) (Changes, error) {
	oldCatalog, newCatalog := current.Catalog(), candidate.Catalog()
	if oldCatalog.permissions == nil || newCatalog.permissions == nil {
		return Changes{}, ErrInvalidCatalog
	}
	var changes Changes
	for key, permission := range newCatalog.permissions {
		old, exists := oldCatalog.permissions[key]
		if !exists {
			changes.AddedPermissions = append(changes.AddedPermissions, key)
		} else if old != permission {
			changes.ChangedPermissions = append(changes.ChangedPermissions, key)
		}
	}
	for key := range oldCatalog.permissions {
		if !newCatalog.Contains(key) {
			changes.RemovedPermissions = append(changes.RemovedPermissions, key)
		}
	}
	oldRoles := make(map[string]RoleTemplate, len(current.definition.RoleTemplates))
	newRoles := make(map[string]RoleTemplate, len(candidate.definition.RoleTemplates))
	for _, role := range current.Templates() {
		slices.Sort(role.Permissions)
		oldRoles[role.Key] = role
	}
	for _, role := range candidate.Templates() {
		slices.Sort(role.Permissions)
		newRoles[role.Key] = role
		old, exists := oldRoles[role.Key]
		if !exists {
			changes.AddedTemplates = append(changes.AddedTemplates, role.Key)
		} else if old.Name != role.Name || old.Description != role.Description || !slices.Equal(old.Permissions, role.Permissions) {
			changes.ChangedTemplates = append(changes.ChangedTemplates, role.Key)
		}
	}
	for key := range oldRoles {
		if _, exists := newRoles[key]; !exists {
			changes.RemovedTemplates = append(changes.RemovedTemplates, key)
		}
	}
	slices.Sort(changes.AddedPermissions)
	slices.Sort(changes.RemovedPermissions)
	slices.Sort(changes.ChangedPermissions)
	slices.Sort(changes.AddedTemplates)
	slices.Sort(changes.RemovedTemplates)
	slices.Sort(changes.ChangedTemplates)
	return changes, nil
}
