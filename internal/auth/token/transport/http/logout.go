package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Revoke the native refresh family and its API session
// @Description Native JSON credential only; no Origin/Cookie/Authorization/query. Repeated or unknown well-formed refresh returns 204. A known current or spent credential revokes only its own family; never logout-all. Does not remove reuse history. Local JWTs remain valid until their published expiry window; strict consumers require online authority.
// @Tags Native tokens
// @Accept json
// @Param body body RefreshRequest true "Opaque refresh credential"
// @Success 204 "Logged out"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/token/logout [post]
func (h *NativeHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var input RefreshRequest
	if !decodeNative(w, r, &input, []string{"refreshToken"}) {
		return
	}
	if err := h.services.Tokens.Logout(r.Context(), service.RefreshInput{Token: input.RefreshToken, IP: httpx.IP(r)}); err != nil {
		h.respondError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
