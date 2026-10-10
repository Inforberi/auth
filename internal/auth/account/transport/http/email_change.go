package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailChangeService interface {
	Request(context.Context, domain.UserID, string, string, string, string) error
	Confirm(context.Context, string, string) error
	Report(context.Context, string, string) error
}

type EmailChangeHandler struct {
	service EmailChangeService
	log     *zap.Logger
}

func NewEmailChange(service EmailChangeService, log *zap.Logger) *EmailChangeHandler {
	return &EmailChangeHandler{service: service, log: log}
}

var emailChangeErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrInvalidEmailChange, 400, "invalid_email_change", "invalid email change"),
	httpx.MatchError(domain.ErrFreshAuthRequired, 401, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(domain.ErrEmailChangePending, 409, "email_change_pending", "email change already pending"),
	{Target: domain.ErrVerificationLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *EmailChangeHandler) respondError(w http.ResponseWriter, r *http.Request, err error, operation string) {
	httpx.RespondError(w, r, h.log, operation, err, emailChangeErrors, dependencyFailure)
}
