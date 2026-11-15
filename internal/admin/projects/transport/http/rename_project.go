package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RenameProjectRequest struct {
	OperationID     domain.ID `json:"operationId" swaggertype:"string"`
	ExpectedVersion int64     `json:"expectedVersion"`
	Name            string    `json:"name"`
	Reason          string    `json:"reason"`
} // @name project_http.RenameProjectRequest

type RenameProjectResponse struct {
	Name     string `json:"name"`
	Version  int64  `json:"version"`
	Replayed bool   `json:"replayed"`
} // @name project_http.RenameProjectResponse

// @Summary Change the display name of a project
// @Tags Platform Projects
// @Param id path string true "Project UUID"
// @Param body body RenameProjectRequest true "Operation UUID, project version, display name and reason"
// @Success 200 {object} RenameProjectResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjectsByIdName
// @Router /api/v1/platform/projects/{id}/name [post]
func (h *Handler) Rename(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	var input RenameProjectRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Rename(r.Context(), actor, domain.Rename{
		ProjectID: domain.ID(chi.URLParam(r, "id")), OperationID: input.OperationID,
		Name: input.Name, ExpectedVersion: input.ExpectedVersion, Reason: input.Reason,
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, RenameProjectResponse(result))
}
