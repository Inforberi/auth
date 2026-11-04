package tokennativehttp

import (
	"net/http"
)

// @Summary Complete a native email second-factor challenge
// @Description Requires the exact challenge/binding from the selected email route and its one-use email code. Recovery=true, TOTP/browser challenges and arbitrary target changes fail closed. Issuance/sign/audit are atomic; the resulting email proof does not satisfy strong-MFA guards.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body NativeMFARequest true "Challenge, binding and email code"
// @Success 200 {object} NativeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/native/mfa/email/complete [post]
func (h *NativeHandler) CompleteEmailMFA(w http.ResponseWriter, r *http.Request) {
	h.CompleteMFA(w, r)
}
