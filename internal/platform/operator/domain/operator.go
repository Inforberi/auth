package domain

import (
	"errors"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type (
	RealmID    string
	Permission string
)

const (
	ProjectsRead    Permission = "platform.projects.read"
	ProjectsManage  Permission = "platform.projects.manage"
	UsersManage     Permission = "platform.project_users.manage"
	AccessManage    Permission = "platform.project_access.manage"
	SettingsManage  Permission = "platform.project_settings.manage"
	OperatorsManage Permission = "platform.operators.manage"
)

var (
	ErrForbidden   = errors.New("platform access forbidden")
	ErrUnavailable = errors.New("platform authority unavailable")
)

type Principal struct {
	UserID    accountdomain.UserID
	TokenHash string
}

func (id RealmID) Valid() bool {
	return id != "00000000-0000-0000-0000-000000000000" && accountdomain.ValidUserID(accountdomain.UserID(id))
}

func (p Permission) Valid() bool {
	switch p {
	case ProjectsRead, ProjectsManage, UsersManage, AccessManage, SettingsManage, OperatorsManage:
		return true
	}
	return false
}

func OwnerPermissions() []Permission {
	return []Permission{ProjectsRead, ProjectsManage, UsersManage, AccessManage, SettingsManage, OperatorsManage}
}
