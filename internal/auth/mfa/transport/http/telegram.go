package mfahttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type telegramManagement interface {
	Request(context.Context, service.Proof, string) (*service.TelegramStarted, error)
	Confirm(context.Context, service.ConfirmTelegramChannel) (*service.TelegramPrepared, error)
	Status(context.Context, service.Proof) (*domain.TelegramFactor, error)
	Enable(context.Context, service.Proof) error
	Disable(context.Context, service.Proof) error
}

func (h *TelegramHandler) change(w http.ResponseWriter, r *http.Request, change func(context.Context, service.Proof) error) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := emailActionProof(w, r)
	if !ok {
		return
	}
	if err := change(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, StatusResponse{Status: "ok"})
}

type TelegramHandler struct {
	service telegramManagement
	log     *zap.Logger
}

func NewTelegram(service telegramManagement, log *zap.Logger) *TelegramHandler {
	return &TelegramHandler{service: service, log: log}
}

var telegramErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidTelegramPreparation, 400, "invalid_telegram_factor", "invalid Telegram channel proof"),
	httpx.MatchError(domain.ErrInvalidPreference, 400, "invalid_mfa_preference", "invalid MFA preference"),
}, emailMFAErrors...)

func (h *TelegramHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	respondMFAError(w, r, h.log, err, telegramErrors)
}
