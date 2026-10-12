package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestRoleValidation(t *testing.T) {
	for _, tc := range []struct {
		name, key, label string
		permissions      []PermissionKey
		want             error
	}{
		{"custom", "report_editor", "Editor", []PermissionKey{"reports.read", "reports.edit"}, nil},
		{"empty permissions", "reader", "Reader", nil, nil},
		{"system key", "super_admin", "Admin", nil, ErrInvalidRole},
		{"invalid key", "Editor", "Editor", nil, ErrInvalidRole},
		{"blank label", "reader", " ", nil, ErrInvalidRole},
		{"oversize label", "reader", strings.Repeat("x", 201), nil, ErrInvalidRole},
		{"duplicate", "reader", "Reader", []PermissionKey{"reports.read", "reports.read"}, ErrInvalidPermission},
		{"wildcard", "reader", "Reader", []PermissionKey{"reports.*"}, ErrInvalidPermission},
		{"too many", "reader", "Reader", make([]PermissionKey, 129), ErrInvalidRole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRole(tc.key, tc.label, "", tc.permissions); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
