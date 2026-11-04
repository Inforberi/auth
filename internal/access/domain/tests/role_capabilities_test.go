package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func TestRoleCapabilitiesRequireKnownPermissionsAndReadyMFA(t *testing.T) {
	known := func(key domain.PermissionKey) bool { return key == "users.read" }
	for _, tc := range []struct {
		name  string
		role  domain.Role
		ready bool
		want  error
	}{
		{"ordinary role", domain.Role{Permissions: []domain.PermissionKey{"users.read"}}, false, nil},
		{"unknown permission precedes unavailable MFA", domain.Role{Permissions: []domain.PermissionKey{"foreign.read"}, MFARequired: true}, false, domain.ErrInvalidPermission},
		{"required MFA unavailable", domain.Role{Permissions: []domain.PermissionKey{"users.read"}, MFARequired: true}, false, domain.ErrMFANotReady},
		{"required MFA ready", domain.Role{Permissions: []domain.PermissionKey{"users.read"}, MFARequired: true}, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) { require.ErrorIs(t, tc.role.RequireCapabilities(known, tc.ready), tc.want) })
	}
}
