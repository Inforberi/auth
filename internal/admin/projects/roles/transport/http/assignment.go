package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PlatformAssignmentRequest struct {
	OperationID           domain.ID `json:"operationId" swaggertype:"string"`
	ExpectedVersion       int64     `json:"expectedVersion"`
	ExpectedGeneration    int64     `json:"expectedGeneration"`
	ExpectedRoleVersion   int64     `json:"expectedRoleVersion"`
	ExpectedAccessVersion int64     `json:"expectedAccessVersion"`
	Reason                string    `json:"reason"`
} // @name project_http.PlatformAssignmentRequest

type PlatformAssignmentResponse struct {
	OperationID     domain.ID             `json:"operationId" swaggertype:"string"`
	ProjectID       domain.ID             `json:"projectId" swaggertype:"string"`
	UserID          accountdomain.UserID  `json:"userId" swaggertype:"string"`
	Action          domain.RoleAction     `json:"action" swaggertype:"string"`
	Status          string                `json:"status"`
	AccessVersion   int64                 `json:"accessVersion,omitempty"`
	Changed         *bool                 `json:"changed,omitempty"`
	Replayed        bool                  `json:"replayed"`
	CatalogRecorded bool                  `json:"catalogRecorded"`
	Role            *PlatformRoleResponse `json:"role,omitempty"`
} // @name project_http.PlatformAssignmentResponse

func (h *RoleHandler) changeAssignment(w http.ResponseWriter, r *http.Request, action domain.RoleAction) {
	actor, ok := cataloghttp.OperationActor(w, r)
	if !ok {
		return
	}
	var input PlatformAssignmentRequest
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	project := domain.ID(chi.URLParam(r, "id"))
	user := accountdomain.UserID(chi.URLParam(r, "userId"))
	result, err := h.service.ChangeRoleAssignment(r.Context(), actor, domain.RoleAssignment{
		OperationID: input.OperationID, ProjectID: project, ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration,
		Action: action, UserID: user, RoleID: accessdomain.RoleID(chi.URLParam(r, "roleId")), ExpectedRoleVersion: input.ExpectedRoleVersion, ExpectedAccessVersion: input.ExpectedAccessVersion, Reason: input.Reason,
	})
	if err != nil && !errors.Is(err, domain.ErrOperationOutcomeUnknown) {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Location", roleOperationLocation(project, input.OperationID))
	response := PlatformAssignmentResponse{
		OperationID: input.OperationID, ProjectID: project, UserID: user, Action: action, Status: "committed",
		AccessVersion: result.AccessVersion, Changed: &result.Changed, Replayed: result.Replayed, CatalogRecorded: result.CatalogRecorded, Role: platformRoleResponse(result.Role),
	}
	status := http.StatusOK
	if err != nil {
		status = http.StatusAccepted
		response.Status = "unknown"
		response.Role = nil
		response.Changed = nil
	}
	httpx.JSON(w, status, response)
}
