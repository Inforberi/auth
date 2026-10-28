package http

import "net/http"

// @Summary Start administrative password login
// @Description Requires a permanent password, verified email and current administrative authority. Saved realm/role policy and enrolled protection decide whether MFA is required. Returns a session for an optional administrator without a factor, otherwise a bound MFA challenge (including limited enrollment when required). Independent of public login methods; does not create an account or assign roles. Uses the public password login rate budget.
// @Tags Administration
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Param body body LoginByEmailRequest true "credentials"
// @Success 200 {object} LoginByEmailResponse
// @Success 202 {object} mfahttp.ChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_credentials"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Router /api/v1/admin/auth/login/email [post]
func (h *PasswordHandler) LoginAdministrator(w http.ResponseWriter, r *http.Request) {
	h.login(w, r, h.service.LoginAdministrator)
}
