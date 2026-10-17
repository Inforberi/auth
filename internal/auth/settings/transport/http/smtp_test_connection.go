package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SMTPTestRequest struct {
	ExpectedVersion int64 `json:"expectedVersion" binding:"required"`
} // @name smtp_settings_http.TestRequest

type SMTPTestResponse struct {
	TestedVersion int64  `json:"testedVersion"`
	Status        string `json:"status"`
} // @name smtp_settings_http.TestResponse

// @Summary Test the saved SMTP connection without sending email
// @Description Requires auth.settings.manage and fresh password+MFA. Tests the authorized saved version only, after releasing SQL locks; greeting/STARTTLS/AUTH/NOOP, not actual delivery. Max 10 seconds, 3/user/minute and 10/project/minute, 2 concurrent tests/instance. Does not store a readiness claim or refresh the session.
// @Tags SMTP settings
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body SMTPTestRequest true "saved SMTP version"
// @Success 200 {object} SMTPTestResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse "smtp_settings_conflict, smtp_connection_failed"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/smtp/test [post]
func (h *SMTPHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input SMTPTestRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.TestConnection(r.Context(), actor, input.ExpectedVersion); err != nil {
		h.respondError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, SMTPTestResponse{TestedVersion: input.ExpectedVersion, Status: "connected"})
}
