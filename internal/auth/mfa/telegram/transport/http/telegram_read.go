package mfatelegramhttp

import (
	"net/http"
	"time"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TelegramFactorResponse struct {
	Allowed    bool       `json:"allowed"`
	Configured bool       `json:"configured"`
	BotID      int64      `json:"botId"`
	TelegramID int64      `json:"telegramId"`
	EnabledAt  *time.Time `json:"enabledAt,omitempty"`
} // @name mfahttp.TelegramFactorResponse

// @Summary Read the current user's Telegram factor
// @Tags MFA
// @Produce json
// @Success 200 {object} TelegramFactorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/telegram [get]
func (h *TelegramHandler) Read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.RequestProof(w, r)
	if !ok {
		return
	}
	result, err := h.service.Status(r.Context(), proof)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, TelegramFactorResponse{Allowed: result.Allowed, Configured: result.Configured, BotID: result.BotID, TelegramID: result.TelegramID, EnabledAt: result.EnabledAt})
}
