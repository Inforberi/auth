package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type provisioningService interface {
	Provision(context.Context, service.ProvisionInput) (*service.ProvisionResult, error)
	ReissueInvitation(context.Context, service.InvitationReissueInput) (*service.ProvisionResult, error)
}

type ProvisioningHandler struct {
	service provisioningService
	log     *zap.Logger
}

func NewProvisioning(service provisioningService, log *zap.Logger) *ProvisioningHandler {
	return &ProvisioningHandler{service: service, log: log}
}

type ProvisionResponse struct {
	UserID domain.UserID `json:"userId" swaggertype:"string"`
	Reused bool          `json:"reused"`
} // @name account_http.ProvisionResponse

var provisioningErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrProvisionDisabled, 404, "method_disabled", "provisioning disabled"),
	httpx.MatchError(domain.ErrProvisionConflict, 409, "provisioning_conflict", "provisioning request conflict"),
	httpx.MatchError(domain.ErrProvisionEmailExists, 409, "email_unavailable", "email unavailable"),
	httpx.MatchError(domain.ErrInvalidInvitation, 409, "target_unavailable", "invitation target unavailable"),
	httpx.MatchError(domain.ErrInvitationCooldown, 409, "issuance_cooldown", "issuance cooldown has not elapsed"),
	httpx.MatchError(domain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
	httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh password and MFA required"),
	{Target: domain.ErrVerificationLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *ProvisioningHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "user_provisioning", err, provisioningErrors, dependencyFailure)
}
