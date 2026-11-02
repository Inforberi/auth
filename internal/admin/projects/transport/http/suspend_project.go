package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

// @Summary Suspend an independent project
// @Description Platform deployment only. Requires current platform.projects.manage and fresh password/MFA proofs. Stores a suspension decision and atomic audit, without deleting storage or sessions. Same committed operation and payload returns its original receipt only after current authority is checked again. Runtime enforcement arrives with MP4; this endpoint alone does not stop an external running service.
// @Tags Platform Projects
// @Accept json
// @Produce json
// @Param Origin header string true "Exact platform HTTPS origin"
// @Param id path string true "Project UUID"
// @Param body body ChangeStateRequest true "Operation UUID, expected version/generation and safe reason (1-500 bytes)"
// @Success 200 {object} TransitionResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited; Retry-After: 60"
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/suspend [post]
func (h *Handler) Suspend(w http.ResponseWriter, r *http.Request) {
	h.changeState(w, r, domain.Suspend)
}
