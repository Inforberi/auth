package mfatelegramhttp

import (
	"net/http"
	"time"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TelegramPreparationResponse struct {
	Binding   string    `json:"binding"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name mfahttp.TelegramPreparationResponse

// @Summary Begin private Telegram factor preparation
// @Tags MFA
// @Produce json
// @Success 202 {object} TelegramPreparationResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/telegram/preparation [post]
func (h *TelegramHandler) Request(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.ActionProof(w, r)
	if !ok {
		return
	}
	result, err := h.service.Request(r.Context(), proof, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, TelegramPreparationResponse{Binding: result.Binding, URL: result.URL, ExpiresAt: result.ExpiresAt})
}
