package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CreateRoleRequest struct {
	Key         string                 `json:"key" binding:"required"`
	Name        string                 `json:"name" binding:"required"`
	Description string                 `json:"description"`
	Permissions []domain.PermissionKey `json:"permissions" swaggertype:"array,string"`
	MFARequired *bool                  `json:"mfaRequired" extensions:"x-nullable"`
} // @name access_http.CreateRoleRequest

// @Summary Create a custom role
// @Description Requires access.roles.manage, all delegated permissions and fresh password plus MFA in the mutation transaction. No system role or wildcard bypass. Duplicate key returns conflict; no automatic assignments.
// @Tags Admin Access
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body CreateRoleRequest true "Custom role"
// @Success 201 {object} RoleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/roles [post]
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input CreateRoleRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	role, err := h.service.CreateRole(r.Context(), service.CreateRoleInput{
		Actor: actor, Key: input.Key, Name: input.Name, Description: input.Description, Permissions: input.Permissions, MFARequired: input.MFARequired,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 201, roleResponse(role))
}
