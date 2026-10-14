package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type initialSetup interface {
	Start(context.Context, service.SetupStartInput) (*service.SetupStarted, error)
	Complete(context.Context, service.SetupCompleteInput) (*service.SetupCompleted, error)
}
type SetupHandler struct {
	service initialSetup
	log     *zap.Logger
}

func NewSetup(service initialSetup, log *zap.Logger) *SetupHandler {
	return &SetupHandler{service: service, log: log}
}

var setupErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrSetupClosed, 404, "setup_closed", "initial setup unavailable"),
	httpx.MatchError(domain.ErrSetupUnauthorized, 403, "setup_unauthorized", "operator proof required"),
	httpx.MatchError(domain.ErrSetupInvalid, 400, "invalid_setup", "invalid setup confirmation"),
	httpx.MatchError(domain.ErrSetupConflict, 409, "setup_conflict", "setup unavailable or retry after one minute"),
	httpx.MatchError(domain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrSetupPasswordPolicy, 400, "invalid_password", "password does not satisfy policy"),
	{Target: domain.ErrVerificationLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": []string{"60"}}}},
}

func (h *SetupHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "initial_setup", err, setupErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
