package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TemporaryCompleteRequest struct {
	Token           string `json:"token"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
} // @name password_http.TemporaryCompleteRequest

// @Summary Set a permanent password after temporary login
// @Description Optional temporary password profile. Consumes a one-time setup token and revokes temporary credentials atomically. Does not create a session, verify email, bypass MFA or grant roles. Use ordinary login afterwards. GET never changes credentials.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body TemporaryCompleteRequest true "setup token and permanent password"
// @Success 200 {object} RecoveryResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_temporary_password, password_mismatch, password_policy, same_password"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/temporary-password/complete [post]
func (h *TemporaryPasswordHandler) Complete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input TemporaryCompleteRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Complete(r.Context(), input.Token, input.Password, input.ConfirmPassword, httpx.IP(r)); err != nil {
		httpx.RespondError(w, r, h.log, "temporary password completion", err, temporaryPasswordErrors, dependencyFailure)
		return
	}
	httpx.JSON(w, 200, RecoveryResponse{Status: "ok"})
}
