package http

import (
	"go.uber.org/zap"

	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
)

const flowCookie = "__Host-telegram-flow"

type Handler struct{ *oidchttp.Handler }

func New(service oidchttp.Authentication, log *zap.Logger) *Handler {
	return &Handler{Handler: oidchttp.New(service, log, flowCookie, "telegram_auth")}
}
