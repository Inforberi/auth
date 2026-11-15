package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CreatePlatformRoleRequest struct {
	OperationID        domain.ID                    `json:"operationId" swaggertype:"string"`
	ExpectedVersion    int64                        `json:"expectedVersion"`
	ExpectedGeneration int64                        `json:"expectedGeneration"`
	Key                string                       `json:"key"`
	Name               string                       `json:"name"`
	Description        string                       `json:"description"`
	Permissions        []accessdomain.PermissionKey `json:"permissions" swaggertype:"array,string"`
	MFARequired        bool                         `json:"mfaRequired"`
	Reason             string                       `json:"reason"`
} // @name project_http.CreatePlatformRoleRequest

type CreatePlatformRoleResponse struct {
	OperationID     domain.ID             `json:"operationId" swaggertype:"string"`
	ProjectID       domain.ID             `json:"projectId" swaggertype:"string"`
	Status          string                `json:"status"`
	Role            *PlatformRoleResponse `json:"role,omitempty"`
	Replayed        bool                  `json:"replayed"`
	CatalogRecorded bool                  `json:"catalogRecorded"`
} // @name project_http.CreatePlatformRoleResponse

// @Summary Create a project role as a platform operator
// @Description Runtime-enabled platform only. Requires current platform.project_access.manage and fresh password/MFA. Exact project version/generation; immutable operation UUID/payload. Target and actor are server-owned. A 202 unknown result may have committed: read/reconcile the same operation, never infer rollback. Known project commit can return catalogRecorded=false. No assignment or project identity is created. Project MFA capability is not yet assembled: mfaRequired=true fails closed with mfa_not_ready. Permission catalog uses deployment-owned ACCESS_CATALOG_FILE.
// @Tags Platform Roles
// @Accept json
// @Produce json
// @Param Origin header string true "Exact platform HTTPS origin"
// @Param id path string true "Project UUID"
// @Param body body CreatePlatformRoleRequest true "Immutable command; maximum 32 KiB"
// @Success 201 {object} CreatePlatformRoleResponse
// @Success 200 {object} CreatePlatformRoleResponse "Committed replay"
// @Success 202 {object} CreatePlatformRoleResponse "Outcome unknown"
// @Header 201 {string} Location "Relative role operation URL"
// @Header 202 {string} Location "Relative role operation URL"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdRoles
// @Router /api/v1/platform/projects/{id}/roles [post]
func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.OperationActor(w, r)
	if !ok {
		return
	}
	var input CreatePlatformRoleRequest
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	project := domain.ID(chi.URLParam(r, "id"))
	result, err := h.service.CreateRole(r.Context(), actor, domain.RoleCreation{
		OperationID: input.OperationID, ProjectID: project, ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration,
		Key: input.Key, Name: input.Name, Description: input.Description, Permissions: input.Permissions, MFARequired: input.MFARequired, Reason: input.Reason,
	})
	if err != nil && !errors.Is(err, domain.ErrOperationOutcomeUnknown) {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Location", roleOperationLocation(project, input.OperationID))
	response := CreatePlatformRoleResponse{OperationID: input.OperationID, ProjectID: project, Status: "committed", Role: platformRoleResponse(result.Role), Replayed: result.Replayed, CatalogRecorded: result.CatalogRecorded}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	if err != nil {
		status = http.StatusAccepted
		response.Status = "unknown"
		response.Role = nil
	}
	httpx.JSON(w, status, response)
}
