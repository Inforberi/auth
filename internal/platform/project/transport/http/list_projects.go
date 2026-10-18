package http

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectPageResponse struct {
	Projects   []ProjectResponse `json:"projects"`
	NextCursor string            `json:"nextCursor"`
} // @name project_http.ProjectPageResponse

// @Summary List independent projects
// @Description Platform deployment only. Requires its current browser session and platform.projects.read; a project role or JWT is not platform authority. No session refresh, fresh-proof renewal or storage probes. Newest createdAt/UUID first, exclusive opaque cursor bound to phase filter. No credentials, binding references, database names, offset or total count.
// @Tags Platform Projects
// @Produce json
// @Param Origin header string false "Optional for GET; if supplied, must be the exact platform HTTPS origin"
// @Param before query string false "Opaque nextCursor from the previous page; retain the same phase filter"
// @Param phase query string false "Preparation phase, not health" Enums(pending,provisioning,failed,ready)
// @Param limit query int false "Page size 1..100, default 50" default(50)
// @Success 200 {object} ProjectPageResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects [get]
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	actor, ok := requestActor(w, r)
	if !ok {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		httpx.Error(w, 400, "invalid_query", "invalid project query")
		return
	}
	for name, values := range query {
		if len(values) != 1 || (name != "limit" && name != "before" && name != "phase") {
			httpx.Error(w, 400, "invalid_query", "invalid project query")
			return
		}
	}
	limit := 50
	if values, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(values[0])
		if err != nil {
			httpx.Error(w, 400, "invalid_query", "invalid project query")
			return
		}
	}
	page, err := h.service.List(r.Context(), actor, service.ListInput{Limit: limit, Before: query.Get("before"), Phase: domain.Phase(query.Get("phase"))})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	response := ProjectPageResponse{Projects: make([]ProjectResponse, 0, len(page.Projects)), NextCursor: page.NextCursor}
	for _, p := range page.Projects {
		response.Projects = append(response.Projects, projectResponse(p))
	}
	httpx.JSON(w, 200, response)
}
