package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
} // @name token_http.RefreshRequest

// @Summary Rotate native refresh and issue an access token
// @Description Native JSON credential only; no Origin/Cookie/Authorization/query. Single-flight required. Replay of a known spent credential commits family/session revocation before 401. No retry/grace on lost responses. First rotation can be immediate, later >=30s; 4096 credentials/family, then sign in again. Does not extend absolute lifetime, scope or assurance.
// @Tags Native tokens
// @Accept json
// @Produce json
// @Param body body RefreshRequest true "Current opaque refresh credential"
// @Success 200 {object} NativeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/token/refresh [post]
func (h *NativeHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var input RefreshRequest
	if !decodeNative(w, r, &input, []string{"refreshToken"}) {
		return
	}
	result, err := h.services.Tokens.Refresh(r.Context(), service.RefreshInput{Token: input.RefreshToken, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	h.writeTokens(w, r, result)
}
