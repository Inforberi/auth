package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CreateProjectRequest struct {
	OperationID domain.ID `json:"operationId" swaggertype:"string"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Reason      string    `json:"reason"`
} // @name project_http.CreateProjectRequest

type CreateProjectResponse struct {
	Project  ProjectResponse `json:"project"`
	Replayed bool            `json:"replayed"`
} // @name project_http.CreateProjectResponse

// @Summary Create an independent project intent
// @Description Platform deployment only. Requires current platform.projects.manage and fresh password/MFA. Persists enabled/pending metadata plus an atomic creation audit/receipt; does not create a database, keys, administrator or running project. Origin is generated from slug and deployment-owned auth domain. Storage target is deployment-owned; arbitrary origin/DSN/credentials are not accepted. Retry the same operation UUID/payload after a lost response. Replay checks current authority and returns the original creation snapshot, not later lifecycle state.
// @Tags Platform Projects
// @Accept json
// @Produce json
// @Param Origin header string true "Exact platform HTTPS origin"
// @Param body body CreateProjectRequest true "Operation UUID, immutable slug, display name and safe reason"
// @Success 201 {object} CreateProjectResponse
// @Success 200 {object} CreateProjectResponse "Committed replay"
// @Header 201 {string} Location "Relative platform project card path"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited; Retry-After: 60"
// @Failure 503 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformProjects
// @Router /api/v1/platform/projects [post]
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 400, "invalid_query", "invalid project query")
		return
	}
	var input CreateProjectRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Create(r.Context(), actor, service.CreateInput{OperationID: input.OperationID, Slug: input.Slug, Name: input.Name, Reason: input.Reason})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	w.Header().Set("Location", "/api/v1/platform/projects/"+string(result.Project.ID))
	httpx.JSON(w, status, CreateProjectResponse{Project: projectResponse(result.Project), Replayed: result.Replayed})
}
