package http

import "net/http"

// @Summary Start administrative password and MFA login
// @Description Requires a permanent password, verified email, enrolled MFA and current administrative authority. Always returns an MFA challenge, never a session. Complete with /api/v1/auth/mfa/login/complete. Independent of public login method settings; does not create an account or assign roles. Uses the public password login rate budget.
// @Tags Administration
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Param body body LoginByEmailRequest true "credentials"
// @Success 202 {object} mfahttp.ChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_credentials"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Router /api/v1/admin/auth/login/email [post]
func (h *PasswordHandler) LoginAdministrator(w http.ResponseWriter, r *http.Request) {
	h.login(w, r, true)
}
