package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type accessService interface {
	PermissionCatalog(context.Context, service.Principal) ([]settings.Permission, error)
	ListManagedRoles(context.Context, service.Principal, string, int) ([]domain.Role, error)
	ReadManagedRole(context.Context, service.Principal, domain.RoleID) (domain.Role, error)
	CreateRole(context.Context, service.CreateRoleInput) (domain.Role, error)
	UpdateRole(context.Context, service.UpdateRoleInput) (domain.Role, error)
	ChangeAssignment(context.Context, service.AssignmentInput) (int64, error)
	ChangeAdministrator(context.Context, service.AdministratorInput) (int64, error)
	UserAccess(context.Context, service.Principal) (domain.UserAccess, error)
	AssignmentAccess(context.Context, service.Principal, accountdomain.UserID) (domain.UserAccess, error)
}

type Handler struct {
	service accessService
	log     *zap.Logger
}

func New(service accessService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func principal(w http.ResponseWriter, r *http.Request) (service.Principal, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return service.Principal{}, false
	}
	return service.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}

type RoleResponse struct {
	ID          domain.RoleID          `json:"id" swaggertype:"string"`
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	System      bool                   `json:"system"`
	Version     int64                  `json:"version"`
	Permissions []domain.PermissionKey `json:"permissions" swaggertype:"array,string"`
} // @name access_http.RoleResponse

func roleResponse(role domain.Role) RoleResponse {
	permissions := role.Permissions
	if permissions == nil {
		permissions = []domain.PermissionKey{}
	}
	return RoleResponse{ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description, System: role.System, Version: role.Version, Permissions: permissions}
}

type AccessResponse struct {
	Version     int64                  `json:"accessVersion"`
	RoleIDs     []domain.RoleID        `json:"roleIds" swaggertype:"array,string"`
	Permissions []domain.PermissionKey `json:"permissions" swaggertype:"array,string"`
} // @name access_http.AccessResponse

func accessResponse(access domain.UserAccess) AccessResponse {
	if access.RoleIDs == nil {
		access.RoleIDs = []domain.RoleID{}
	}
	if access.Permissions == nil {
		access.Permissions = []domain.PermissionKey{}
	}
	return AccessResponse{Version: access.Version, RoleIDs: access.RoleIDs, Permissions: access.Permissions}
}
