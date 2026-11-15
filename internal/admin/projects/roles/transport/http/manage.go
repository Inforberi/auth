package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	access "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RoleManagement interface {
	EditRole(context.Context, operators.Principal, domain.DirectoryTarget, access.RoleID, int64, access.RoleChange) (access.Role, error)
	ChangeProjectAdministrator(context.Context, operators.Principal, domain.DirectoryTarget, accessservice.AdministratorInput) (int64, error)
}

func (h *RoleHandler) WithManagement(backend RoleManagement) *RoleHandler {
	h.management = backend
	return h
}

type EditRoleRequest struct {
	ExpectedRoleVersion int64                  `json:"expectedRoleVersion"`
	Key                 string                 `json:"key"`
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Permissions         []access.PermissionKey `json:"permissions" swaggertype:"array,string"`
	MFARequired         *bool                  `json:"mfaRequired,omitempty"`
} // @name project_http.EditRoleRequest

// @Summary Replace a project role definition
// @Tags Platform Roles
// @Param id path string true "Project UUID"
// @Param roleId path string true "Role UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body EditRoleRequest true "Role definition and current role version"
// @Success 200 {object} PlatformRoleResponse
// @Security SessionCookie
// @ID putPlatformProjectsByIdRolesByRoleId
// @Router /api/v1/platform/projects/{id}/roles/{roleId} [put]
func (h *RoleHandler) Edit(w http.ResponseWriter, r *http.Request) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var body EditRoleRequest
	if err := httpx.DecodeJSON(w, r, &body); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.management == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	result, err := h.management.EditRole(r.Context(), actor, target, access.RoleID(chi.URLParam(r, "roleId")), body.ExpectedRoleVersion,
		access.RoleChange{Key: body.Key, Name: body.Name, Description: body.Description, Permissions: body.Permissions, MFARequired: body.MFARequired})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, platformRoleResponse(result))
}

type AdministratorRequest struct {
	ExpectedRoleVersion   int64               `json:"expectedRoleVersion"`
	ExpectedAccessVersion int64               `json:"expectedAccessVersion"`
	ExpectedAuthVersion   account.AuthVersion `json:"expectedAuthVersion" swaggertype:"integer"`
	Grant                 *bool               `json:"grant"`
} // @name project_http.AdministratorRequest

type AdministratorResponse struct {
	AccessVersion int64 `json:"accessVersion"`
} // @name project_http.AdministratorResponse

// @Summary Grant or revoke project system administrator
// @Tags Platform Roles
// @Param id path string true "Project UUID"
// @Param userId path string true "User UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param body body AdministratorRequest true "Grant or revoke and current versions"
// @Success 200 {object} AdministratorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdUsersByUserIdAdministrator
// @Router /api/v1/platform/projects/{id}/users/{userId}/administrator [post]
func (h *RoleHandler) ChangeAdministrator(w http.ResponseWriter, r *http.Request) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var body AdministratorRequest
	if err := httpx.DecodeJSON(w, r, &body); err != nil || body.Grant == nil {
		httpx.Error(w, 400, "invalid_request", "invalid administrator request")
		return
	}
	if h.management == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	version, err := h.management.ChangeProjectAdministrator(r.Context(), actor, target, accessservice.AdministratorInput{
		UserID: account.UserID(chi.URLParam(r, "userId")), ExpectedRoleVersion: body.ExpectedRoleVersion,
		ExpectedAccessVersion: body.ExpectedAccessVersion, ExpectedAuthVersion: body.ExpectedAuthVersion, Grant: *body.Grant,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, AdministratorResponse{AccessVersion: version})
}
