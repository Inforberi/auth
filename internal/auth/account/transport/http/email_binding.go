package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type emailBinding interface {
	Request(context.Context, service.EmailBindingInput) (time.Time, error)
	Confirm(context.Context, mfaservice.Proof, string, string) error
}

type EmailBindingHandler struct {
	service emailBinding
	log     *zap.Logger
}

func NewEmailBinding(service emailBinding, log *zap.Logger) *EmailBindingHandler {
	return &EmailBindingHandler{service: service, log: log}
}

func bindingOwner(w http.ResponseWriter, r *http.Request) (sessionhttp.Auth, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
	}
	return auth, ok
}

var bindingErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrEmailBindingDisabled, 404, "method_disabled", "email binding disabled"),
	httpx.MatchError(domain.ErrInvalidEmailBinding, 400, "invalid_email_binding", "invalid email binding"),
	httpx.MatchError(domain.ErrEmailBindingConflict, 409, "email_binding_conflict", "email binding unavailable"),
	httpx.MatchError(domain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
}, resendErrors...)

func (h *EmailBindingHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "email_binding", err, bindingErrors, dependencyFailure)
}
