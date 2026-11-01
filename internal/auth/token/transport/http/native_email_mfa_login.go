package http

import "net/http"

// @Summary Sign in with password and an explicitly selected email factor
// @Description Cookie-free native route. Requires an enrolled allowed email factor after a password; never falls back to password-only tokens. Email is not strong TOTP assurance. Recovery of a lost channel uses the browser operator-assisted flow.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativePasswordRequest true "Password and resource scope"
// @Success 202 {object} NativeChallengeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/mfa/email/login [post]
func (h *NativeHandler) PasswordEmailMFA(w http.ResponseWriter, r *http.Request) {
	h.Password(w, r)
}
