package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const flowCookie = "__Host-telegram-flow"

type telegramService interface {
	Start(context.Context, string) (*service.StartedFlow, error)
	StartLink(context.Context, accountdomain.UserID, string, string) (*service.StartedFlow, error)
	Unlink(context.Context, accountdomain.UserID, string, string) error
	Callback(context.Context, service.CallbackInput) (*service.CallbackResult, error)
}

type Handler struct {
	service telegramService
	log     *zap.Logger
}

func New(service telegramService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func setFlowCookie(w http.ResponseWriter, binding string) {
	cookie := &http.Cookie{
		Name: flowCookie, Value: binding, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(service.FlowTTL),
	}
	if binding == "" {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, cookie)
}

var telegramErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrDisabled, 404, "method_disabled", "login method disabled"),
	httpx.MatchError(domain.ErrInvalidFlow, 400, "invalid_login", "invalid login"),
	httpx.MatchError(accountdomain.ErrInvalidIdentity, 400, "invalid_login", "invalid login"),
	httpx.MatchError(accountdomain.ErrIdentityNotFound, 400, "invalid_login", "invalid login"),
	httpx.MatchError(accountdomain.ErrIdentityUnavailable, 400, "invalid_login", "invalid login"),
	httpx.MatchError(accountdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(accountdomain.ErrIdentityConflict, 409, "identity_conflict", "identity already linked"),
	httpx.MatchError(accountdomain.ErrLastLoginMethod, 409, "last_login_method", "cannot remove last login method"),
	httpx.MatchError(sessiondomain.ErrSessionNotFound, 400, "invalid_login", "invalid login"),
	{Target: domain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "telegram_auth", err, telegramErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
