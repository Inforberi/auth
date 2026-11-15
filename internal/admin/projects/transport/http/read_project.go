package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read an independent project
// @Description Platform deployment only. Requires its current browser session and platform.projects.read. Returns stored lifecycle metadata, not storage readiness or credentials. Pending, failed and suspended projects remain visible to an authorized operator. Does not open the project DB, renew a session or expose storage target/database/credential references.
// @Tags Platform Projects
// @Produce json
// @Param Origin header string false "Optional for GET; if supplied, must be the exact platform HTTPS origin"
// @Param id path string true "Project UUID"
// @Success 200 {object} ProjectResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited; Retry-After: 60"
// @Failure 503 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID getPlatformProjectsById
// @Router /api/v1/platform/projects/{id} [get]
func (h *Handler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := RequestActor(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		httpx.Error(w, 400, "invalid_query", "invalid project query")
		return
	}
	p, err := h.service.Read(r.Context(), actor, domain.ID(chi.URLParam(r, "id")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, projectResponse(p))
}
