package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read my effective permissions
// @Description Current SQL role IDs, known permissions and assignment version, for this authenticated user only. The version is not a cache key for role contents. This response helps UI presentation; the backend must authorize every protected operation itself.
// @Tags Access
// @Produce json
// @Success 200 {object} AccessResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/access [get]
func (h *Handler) MyAccess(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	access, err := h.service.UserAccess(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, accessResponse(access))
}
