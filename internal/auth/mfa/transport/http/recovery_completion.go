package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type CompleteRecoveryRequest struct {
	RequestID string `json:"requestId"`
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
} // @name mfa_http.CompleteRecoveryRequest

// @Summary Complete operator-assisted MFA replacement
// @Description Requires the same primary challenge/browser, exact current operator-approved request and new TOTP. Rechecks method/status/version/operator identity and membership. Atomically replaces factor/recovery codes, revokes sessions and records audit/durable verified-contact notification. Returns codes once, clears old cookies, never issues a session or disables MFA. Expired, unapproved, cancelled, foreign and replayed requests share invalid_mfa. Five wrong codes exhaust the request and account guessing budget is shared with normal MFA login. Missing verified contact requires independent operator notification.
// @Tags MFA
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body CompleteRecoveryRequest true "request, primary challenge and new TOTP"
// @Success 200 {object} RecoveryCodesResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_mfa"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 404 {string} string "route absent when disabled"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/mfa/recovery/complete [post]
func (h *Handler) CompleteRecovery(w http.ResponseWriter, r *http.Request) {
	if h.recovery == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var input CompleteRecoveryRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.recovery.Complete(r.Context(), service.CompleteRecoveryInput{RequestID: input.RequestID, Token: input.Challenge, Binding: loginBinding(r), Code: input.Code, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	clearLoginCookie(w)
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryCodesResponse{Codes: result.Codes})
}
