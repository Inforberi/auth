package domain_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func TestRoleChangeSessionInvalidation(t *testing.T) {
	mfaRequired := true
	base := domain.Role{ID: "role", Key: "reader", Name: "Reader", Version: 7, Permissions: []domain.PermissionKey{"reports.read", "users.read"}}
	for _, tc := range []struct {
		name              string
		permissions       []domain.PermissionKey
		mfa               *bool
		rename            bool
		changed, elevated bool
	}{
		{name: "reordered no-op", permissions: []domain.PermissionKey{"users.read", "reports.read"}},
		{name: "metadata only", permissions: base.Permissions, rename: true, changed: true},
		{name: "removal", permissions: []domain.PermissionKey{"reports.read"}, changed: true},
		{name: "replacement", permissions: []domain.PermissionKey{"reports.write"}, changed: true, elevated: true},
		{name: "MFA strengthened", permissions: base.Permissions, mfa: &mfaRequired, changed: true, elevated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			change := domain.RoleChange{Key: base.Key, Name: base.Name, Permissions: tc.permissions, MFARequired: tc.mfa}
			if tc.rename {
				change.Name = "Renamed"
			}
			original := append([]domain.PermissionKey(nil), tc.permissions...)
			next, changed, elevated, err := change.Apply(base, true)
			if err != nil || changed != tc.changed || elevated != tc.elevated {
				t.Fatalf("changed=%v elevated=%v err=%v", changed, elevated, err)
			}
			if next.ID != base.ID || next.Version != base.Version || !reflect.DeepEqual(tc.permissions, original) {
				t.Fatal("identity/version or caller permissions mutated")
			}
			if changed && len(next.Permissions) > 0 {
				next.Permissions[0] = "changed"
				if !reflect.DeepEqual(tc.permissions, original) {
					t.Fatal("replacement aliases input")
				}
			}
		})
	}
}

func TestRoleChangeReadinessBeforeNoOp(t *testing.T) {
	current := domain.Role{Key: "reader", Name: "Reader", MFARequired: true}
	change := domain.RoleChange{Key: current.Key, Name: current.Name}
	if _, _, _, err := change.Apply(current, false); !errors.Is(err, domain.ErrMFANotReady) {
		t.Fatal("unready unchanged MFA role accepted", err)
	}
	mfaOptional := false
	change.MFARequired = &mfaOptional
	next, changed, elevated, err := change.Apply(current, false)
	if err != nil || !changed || elevated || next.MFARequired {
		t.Fatal("MFA relaxation needs no readiness or revision bump", err)
	}
}
