package domain

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

type RoleID string
type PermissionKey string

const MaxRolePermissions = 128

var (
	ErrInvalidRole = errors.New("invalid role")
	ErrForbidden = errors.New("access forbidden")
	ErrRoleNotFound = errors.New("role not found")
	ErrInvalidPermission = errors.New("invalid permission")
	keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
)

type Role struct {
	ID RoleID
	Key string
	Name string
	Description string
	System bool
	Version int64
	Permissions []PermissionKey
}

func ValidKey(key string) bool {
	return len(key) <= 96 && keyPattern.MatchString(key)
}

func ValidateRole(key, name, description string, permissions []PermissionKey) error {
	if !ValidKey(key) || key == "super_admin" || !utf8.ValidString(name) ||
		!utf8.ValidString(description) || strings.TrimSpace(name) == "" ||
		len(name) > 200 || len(description) > 2000 || len(permissions) > MaxRolePermissions {
		return ErrInvalidRole
	}
	seen := make(map[PermissionKey]struct{}, len(permissions))
	for _, key := range permissions {
		if !ValidKey(string(key)) {
			return ErrInvalidPermission
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalidPermission
		}
		seen[key] = struct{}{}
	}
	return nil
}
