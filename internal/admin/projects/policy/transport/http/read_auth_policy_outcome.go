package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read the caller's authentication-policy operation result
// @Description Requires current platform.project_settings.manage and fresh password/MFA. Exact project/caller/operation scope is checked before opening a project connection; current binding and authority are checked again before disclosure. Reads the immutable project receipt and verifies its original durable admission. status=unknown means no committed receipt was found, not rollback. Project must be online/ready with the original binding/version; no offline catalog completion cache. Never re-executes a mutation or creates an admission. Returned policy is historical evidence, not the current policy or current access.
// @Tags Platform Auth settings
// @Produce json
// @Param id path string true "Project UUID"
// @Param operationId path string true "Operation UUID"
// @Success 200 {object} ProjectAuthPolicyResponse{settings=settingshttp.SettingsResponse}
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/auth/settings/operations/{operationId} [get]
func (h *AuthPolicyHandler) ReadOutcome(w http.ResponseWriter, r *http.Request) {
	actor, ok := cataloghttp.OperationActor(w, r)
	if !ok || !cataloghttp.EmptyRequestBody(w, r) {
		return
	}
	result, err := h.service.ReadAuthPolicyOutcome(r.Context(), actor, domain.ID(chi.URLParam(r, "id")), domain.ID(chi.URLParam(r, "operationId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, h.result(result.OperationID, result.Committed, result.AuthPolicyResult))
}
