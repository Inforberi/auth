package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

const flowCookie = "__Host-email-otp"

type emailOTPService interface {
	Request(context.Context, string, string) (*service.RequestedCode, error)
	Confirm(context.Context, service.ConfirmInput) (*sessionservice.CreatedSession, error)
	RequestReauthentication(context.Context, mfaservice.Proof, string, string) (*service.RequestedCode, error)
	ConfirmReauthentication(context.Context, service.ReauthenticationInput) (*service.ReauthenticatedSession, error)
}

type Handler struct {
	service emailOTPService
	log     *zap.Logger
}

type StatusResponse struct {
	Status string `json:"status"`
} // @name emailotp_http.StatusResponse

func New(service emailOTPService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func setFlowCookie(w http.ResponseWriter, value string, expires time.Time) {
	setNamedFlowCookie(w, flowCookie, value, expires)
}

func setNamedFlowCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
}

var errorRules = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrDisabled, 404, "method_disabled", "login method disabled"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrInvalidCode, 400, "invalid_email_login", "invalid email login"),
	httpx.MatchError(sessiondomain.ErrSessionNotFound, 400, "invalid_email_login", "invalid email login"),
	{Target: domain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if mfahttp.RespondLoginError(w, r, h.log, err) {
		return
	}
	httpx.RespondError(w, r, h.log, "email_otp", err, errorRules,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
