package domain

const MaxUserRoles = 32

type UserAccess struct {
	Version     int64
	RoleIDs     []RoleID
	Permissions []PermissionKey
}
