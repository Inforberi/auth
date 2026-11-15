package settingshttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type MFAUpdateRequest struct {
	ExpectedVersion int64         `json:"expectedVersion" binding:"required"`
	Policy          *MFAPolicyDTO `json:"policy" binding:"required"`
} // @name mfa_settings_http.UpdateRequest

// @Summary Change realm MFA policy
// @Description Requires current realm permission, fresh password and fresh MFA when required by policy, role or personal enrollment. expectedVersion prevents lost updates. Required modes need server-owned MFA capability. Strengthening invalidates all previous realm sessions and pending login challenges, including this caller; response still returns the committed policy. A no-op creates no audit/version change. Weakening preserves personal factors and never revives old sessions. No client-supplied capability or actor is accepted.
// @Tags MFA settings
// @Accept json
// @Produce json
// @Param body body MFAUpdateRequest true "Complete mode and current version"
// @Success 200 {object} MFASettingsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse "mfa_policy_conflict, mfa_not_ready"
// @Failure 503 {object} httpx.ErrorResponse
// @ID postAdminAuthSettingsMfa
// @Router /api/v1/admin/auth/settings/mfa [post]
func (h *MFAHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := Principal(w, r)
	if !ok {
		return
	}
	var input MFAUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
		httpx.Error(w, 400, "invalid_json", "complete MFA policy required")
		return
	}
	result, err := h.service.Update(r.Context(), service.MFAUpdateInput{Actor: actor, MFAChange: service.MFAChange{
		ExpectedVersion: input.ExpectedVersion, Policy: domain.MFAPolicy{Mode: input.Policy.Mode},
	}})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}

// @Summary Change realm MFA policy
// @Description Requires current realm permission, fresh password and fresh MFA when required by policy, role or personal enrollment. expectedVersion prevents lost updates. Required modes need server-owned MFA capability. Strengthening invalidates all previous realm sessions and pending login challenges, including this caller; response still returns the committed policy. A no-op creates no audit/version change. Weakening preserves personal factors and never revives old sessions. No client-supplied capability or actor is accepted.
// @Tags MFA settings
// @Accept json
// @Produce json
// @Param body body MFAUpdateRequest true "Complete mode and current version"
// @Success 200 {object} MFASettingsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse "mfa_policy_conflict, mfa_not_ready"
// @Failure 503 {object} httpx.ErrorResponse
// @Security SessionCookie
// @ID postPlatformSettingsMfa
// @Router /api/v1/platform/settings/mfa [post]
func (h *MFAHandler) UpdatePlatform(w http.ResponseWriter, r *http.Request) {
	h.Update(w, r)
}
