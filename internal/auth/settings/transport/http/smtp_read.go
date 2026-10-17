package http

import "net/http"

// @Summary Read SMTP settings without the password
// @Description Requires a live session, HTTPS Origin and auth.settings.manage. passwordSet is presence only. No secrets, session refresh or network tests.
// @Tags SMTP settings
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Success 200 {object} SMTPResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/smtp [get]
func (h *SMTPHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.Read(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.respond(w, result)
}
