package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RetentionUpdateRequest struct {
	ExpectedVersion   int64               `json:"expectedVersion" binding:"required"`
	Policy            *RetentionPolicyDTO `json:"policy" binding:"required"`
	ConfirmShortening bool                `json:"confirmShortening"`
} // @name retention_settings_http.UpdateRequest

// @Summary Update data retention periods
// @Description Requires auth.settings.manage, fresh password+MFA and expectedVersion. All periods must be 1..106751 days. Shortening any period requires confirmShortening=true and can cause irreversible deletion. Each subsequent worker batch reads current SQL settings; an already started batch can use the old snapshot within its five-second deadline. Existing session deadlines and transient challenge expiry do not change.
// @Tags Retention settings
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body RetentionUpdateRequest true "Complete retention policy and current version"
// @Success 200 {object} RetentionResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse "retention_settings_conflict, retention_confirmation_required"
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/retention [post]
func (h *RetentionHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input RetentionUpdateRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil || input.Policy == nil {
		httpx.Error(w, 400, "invalid_json", "complete retention settings required")
		return
	}
	p := input.Policy
	result, err := h.service.Update(r.Context(), service.RetentionUpdateInput{
		Actor: actor, ExpectedVersion: input.ExpectedVersion, ConfirmShortening: input.ConfirmShortening,
		Policy: domain.RetentionPolicy{EmailReservationDays: p.EmailReservationDays, SessionDays: p.SessionDays, SecurityAuditDays: p.SecurityAuditDays},
	})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
