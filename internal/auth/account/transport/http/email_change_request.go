package http

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailChangeRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
} // @name account_http.EmailChangeRequest

// @Summary Request a login email change
// @Description Optional EMAIL_CHANGE_ENABLED profile. Requires a valid session, allowed Origin, verified current login email and either current password or recent session-bound password reauthentication. Omit password after successful reauthentication; a supplied wrong password is always rejected. Old email remains active until confirmation. Sends separate confirmation and security links; no tokens returned.
// @Tags Account
// @Accept json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Produce json
// @Param body body EmailChangeRequest true "new email, optional current password when already reauthenticated"
// @Success 202 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email, invalid_email_change"
// @Failure 401 {object} httpx.ErrorResponse "codes: unauthorized, fresh_auth_required"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 409 {object} httpx.ErrorResponse "code: email_change_pending"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/change [post]
func (h *EmailChangeHandler) Request(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return
	}
	var input EmailChangeRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Request(r.Context(), auth.UserID, auth.TokenHash, input.Email, input.Password, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "request email change")
		return
	}
	httpx.JSON(w, 202, VerificationResponse{Status: "accepted"})
}
