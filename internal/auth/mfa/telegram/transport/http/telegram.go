package mfatelegramhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type telegramManagement interface {
	Request(context.Context, mfaservice.Proof, string) (*mfatelegram.TelegramStarted, error)
	Confirm(context.Context, mfatelegram.ConfirmTelegramChannel) (*mfatelegram.TelegramPrepared, error)
	Status(context.Context, mfaservice.Proof) (*domain.TelegramFactor, error)
	Enable(context.Context, mfaservice.Proof) error
	Disable(context.Context, mfaservice.Proof) error
}

func (h *TelegramHandler) change(w http.ResponseWriter, r *http.Request, change func(context.Context, mfaservice.Proof) error) {
	w.Header().Set("Cache-Control", "no-store")
	proof, ok := mfahttp.ActionProof(w, r)
	if !ok {
		return
	}
	if err := change(r.Context(), proof); err != nil {
		h.respondError(w, r, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, mfahttp.StatusResponse{Status: "ok"})
}

type TelegramHandler struct {
	service telegramManagement
	log     *zap.Logger
}

func NewTelegram(service telegramManagement, log *zap.Logger) *TelegramHandler {
	return &TelegramHandler{service: service, log: log}
}

func (h *TelegramHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	mfahttp.RespondTelegramError(w, r, h.log, err)
}
