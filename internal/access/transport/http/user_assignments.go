package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a user's role assignments and permission union
// @Description Requires current access.assignments.manage. UUID lookup only, no user enumeration. One SQL statement checks actor session/permission and reads the target. Unknown/deleted target and unauthorized actor share forbidden. Pending/blocked targets may have assignments but cannot exercise permissions. accessVersion is for assignment concurrency, not permission caching.
// @Tags Admin Access
// @Produce json
// @Param id path string true "Target user UUID"
// @Success 200 {object} AccessResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/access [get]
func (h *Handler) UserAssignments(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	access, err := h.service.AssignmentAccess(r.Context(), actor, accountdomain.UserID(chi.URLParam(r, "id")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, accessResponse(access))
}
