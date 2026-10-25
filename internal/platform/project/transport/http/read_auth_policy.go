package http

import (
	"net/http"

	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a project's public authentication policy
// @Description Requires current platform.project_settings.manage and fresh password/MFA before read and before disclosure. Exact ready/enabled target version/generation; readonly snapshot. No secret values or project actor impersonation. availableMethods reflects actual trusted assembly, not stored enable switches. Current project Auth assembly is incomplete, so production bridge reports all methods unavailable. GET never initializes missing settings or renews sessions.
// @Tags Platform Auth settings
// @Produce json
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} http.SettingsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/auth/settings [get]
func (h *AuthPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := requestActor(w, r)
	if !ok || !emptyRequestBody(w, r) {
		return
	}
	_, target, ok := directoryQuery(w, r)
	if !ok {
		return
	}
	snapshot, err := h.service.ReadAuthPolicy(r.Context(), actor, target)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, settingshttp.SettingsResponseFrom(snapshot, h.available))
}
