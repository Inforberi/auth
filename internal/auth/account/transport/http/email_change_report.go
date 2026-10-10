package http

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailChangeReportRequest struct {
	Token string `json:"token"`
} // @name account_http.EmailChangeReportRequest

// @Summary Report an unauthorized email change
// @Description Optional profile. Explicit POST with a distinct old-verified-address one-time token; does not require the compromised session. Cancels pending change and revokes sessions, or blocks the account after completion. Never rolls back email, unblocks or signs in automatically. Protected recovery remains a separate release gate.
// @Tags Account
// @Accept json
// @Produce json
// @Param body body EmailChangeReportRequest true "security token"
// @Success 200 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email_change"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/change/report [post]
func (h *EmailChangeHandler) Report(w http.ResponseWriter, r *http.Request) {
	var input EmailChangeReportRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Report(r.Context(), input.Token, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "report email change")
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, VerificationResponse{Status: "ok"})
}
