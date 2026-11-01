package mfahttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TelegramConfirmRequest struct {
	Binding string `json:"binding"`
	Code    string `json:"code"`
}

// @Summary Confirm Telegram possession in the original browser
// @Tags MFA
// @Accept json
// @Produce json
// @Param body body TelegramConfirmRequest true "binding and code"
// @Success 200 {object} StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/telegram/preparation/confirm [post]
func (h *TelegramHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := requestProof(w, r)
	if !ok {
		return
	}
	var input TelegramConfirmRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Confirm(r.Context(), service.ConfirmTelegramChannel{Proof: proof, Binding: input.Binding, Code: input.Code, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}
