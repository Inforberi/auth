package domain_test

import (
	"errors"
	"strings"
	"testing"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func TestRoleValidation(t *testing.T) {
	for _, tc := range []struct {
		name, key, label string
		permissions      []accessdomain.PermissionKey
		want             error
	}{
		{"custom", "report_editor", "Editor", []accessdomain.PermissionKey{"reports.read", "reports.edit"}, nil},
		{"empty permissions", "reader", "Reader", nil, nil},
		{"system key", "super_admin", "Admin", nil, accessdomain.ErrInvalidRole},
		{"invalid key", "Editor", "Editor", nil, accessdomain.ErrInvalidRole},
		{"blank label", "reader", " ", nil, accessdomain.ErrInvalidRole},
		{"oversize label", "reader", strings.Repeat("x", 201), nil, accessdomain.ErrInvalidRole},
		{"duplicate", "reader", "Reader", []accessdomain.PermissionKey{"reports.read", "reports.read"}, accessdomain.ErrInvalidPermission},
		{"wildcard", "reader", "Reader", []accessdomain.PermissionKey{"reports.*"}, accessdomain.ErrInvalidPermission},
		{"too many", "reader", "Reader", make([]accessdomain.PermissionKey, 129), accessdomain.ErrInvalidRole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := accessdomain.ValidateRole(tc.key, tc.label, "", tc.permissions); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
