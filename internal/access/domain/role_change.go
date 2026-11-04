package domain

import "slices"

// RoleChange is applied after authority, version and delegation checks against
// the locked role. A nil MFARequired preserves its current requirement.
type RoleChange struct {
	Key, Name, Description string
	Permissions            []PermissionKey
	MFARequired            *bool
}

// Apply returns the replacement, whether it changed, and whether existing
// sessions need a revision bump. Caller-owned permission slices are not sorted.
func (c RoleChange) Apply(current Role, mfaReady bool) (Role, bool, bool, error) {
	next := current
	if c.MFARequired != nil {
		next.MFARequired = *c.MFARequired
	}
	if next.MFARequired && !mfaReady {
		return Role{}, false, false, ErrMFANotReady
	}
	requested := slices.Clone(c.Permissions)
	slices.Sort(requested)
	if current.Key == c.Key && current.Name == c.Name && current.Description == c.Description && current.MFARequired == next.MFARequired && slices.Equal(current.Permissions, requested) {
		return current, false, false, nil
	}
	next.Key, next.Name, next.Description, next.Permissions = c.Key, c.Name, c.Description, requested
	elevated := (!current.MFARequired && next.MFARequired) || slices.ContainsFunc(requested, func(key PermissionKey) bool {
		return !slices.Contains(current.Permissions, key)
	})
	return next, true, elevated, nil
}
