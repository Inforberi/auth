package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type UpdateRoleRequest struct {
	Key             string                 `json:"key" binding:"required"`
	Name            string                 `json:"name" binding:"required"`
	Description     string                 `json:"description"`
	Permissions     []domain.PermissionKey `json:"permissions" swaggertype:"array,string"`
	ExpectedVersion int64                  `json:"expectedVersion" binding:"required"`
	MFARequired     *bool                  `json:"mfaRequired" extensions:"x-nullable"`
} // @name access_http.UpdateRoleRequest

// @Summary Replace a custom role's definition
// @Description Replaces the definition; omitted/null mfaRequired preserves its previous value for older clients. Requires access.roles.manage, old and new delegated permissions, fresh password plus MFA and current role version in one transaction. Enabling required MFA invalidates old role-bound sessions. A no-op preserves the version; system roles cannot be changed.
// @Tags Admin Access
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Role UUID"
// @Param body body UpdateRoleRequest true "Definition and expected version"
// @Success 200 {object} RoleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/roles/{id} [post]
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input UpdateRoleRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	role, err := h.service.UpdateRole(r.Context(), service.UpdateRoleInput{
		CreateRoleInput: service.CreateRoleInput{Actor: actor, Key: input.Key, Name: input.Name, Description: input.Description, Permissions: input.Permissions, MFARequired: input.MFARequired},
		RoleID:          domain.RoleID(chi.URLParam(r, "id")), ExpectedVersion: input.ExpectedVersion,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, roleResponse(role))
}
