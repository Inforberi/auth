package domain

func (r Role) RequireCapabilities(known func(PermissionKey) bool, mfaReady bool) error {
	for _, permission := range r.Permissions {
		if !known(permission) {
			return ErrInvalidPermission
		}
	}
	if r.MFARequired && !mfaReady {
		return ErrMFANotReady
	}
	return nil
}
