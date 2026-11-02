package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a project's public authentication policy
// @Description Requires current platform.project_settings.manage and fresh password/MFA before read and disclosure. Exact ready/enabled target version/generation. availableMethods/tokenProfiles/readiness are target-specific trusted assembly observations, independent of stored enable switches; dependencies are rechecked when saving policy. Password verification has a separate readiness prerequisite. No secrets or external delivery guarantee; HTTP-disabled deployment reports closed capabilities. GET never initializes settings or renews sessions.
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
	actor, ok := cataloghttp.RequestActor(w, r)
	if !ok || !cataloghttp.EmptyRequestBody(w, r) {
		return
	}
	_, target, ok := cataloghttp.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var view domain.AuthPolicyView
	var readiness *domain.AuthPolicyReadiness
	var err error
	if h.inspection != nil {
		view, err = h.inspection.ReadAuthPolicyView(r.Context(), actor, target)
		readiness = &view.Readiness
	} else {
		view.Snapshot, err = h.service.ReadAuthPolicy(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, h.settings(view.Snapshot, readiness))
}
