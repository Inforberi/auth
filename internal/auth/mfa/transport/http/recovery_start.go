package mfahttp

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type StartRecoveryRequest struct {
	Challenge string `json:"challenge"`
} // @name mfa_http.StartRecoveryRequest

type RecoveryCandidateResponse struct {
	Status    string    `json:"status"`
	RequestID string    `json:"requestId"`
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfa_http.RecoveryCandidateResponse

// @Summary Request operator-assisted MFA replacement
// @Description Opt-in MFA_RECOVERY_ENABLED. Requires a live primary login challenge, its single browser cookie and allowed Origin, not a session. Returns a new candidate once; old MFA stays active. Reissue discards old approval without extending the primary TTL. Independent owner verification and CLI approval are required before completion. No user UUID, actor, version or approved flag accepted.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body StartRecoveryRequest true "primary login challenge"
// @Success 200 {object} RecoveryCandidateResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_mfa"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 404 {string} string "route absent when disabled"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/mfa/recovery/start [post]
func (h *Handler) StartRecovery(w http.ResponseWriter, r *http.Request) {
	if h.recovery == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var input StartRecoveryRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.recovery.Start(r.Context(), service.StartRecoveryInput{Token: input.Challenge, Binding: loginBinding(r), IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, RecoveryCandidateResponse{Status: "operator_approval_required", RequestID: result.RequestID, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
