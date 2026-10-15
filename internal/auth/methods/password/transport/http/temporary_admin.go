package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type temporaryAdminService interface {
	Provision(context.Context, service.TemporaryProvisionInput) (*service.TemporaryIssueResult, error)
	Reissue(context.Context, service.TemporaryReissueInput) (*service.TemporaryIssueResult, error)
}

type TemporaryAdminHandler struct {
	service temporaryAdminService
	log     *zap.Logger
}

func NewTemporaryAdmin(service temporaryAdminService, log *zap.Logger) *TemporaryAdminHandler {
	return &TemporaryAdminHandler{service: service, log: log}
}

type TemporaryIssueResponse struct {
	UserID    accountdomain.UserID `json:"userId" swaggertype:"string"`
	Reused    bool                 `json:"reused"`
	ExpiresAt *time.Time           `json:"expiresAt,omitempty"`
	Password  string               `json:"password,omitempty"`
} // @name password_http.TemporaryIssueResponse

func temporaryAdminActor(w http.ResponseWriter, r *http.Request) (accessservice.Principal, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return accessservice.Principal{}, false
	}
	return accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}

func temporaryIssueResponse(result *service.TemporaryIssueResult) TemporaryIssueResponse {
	response := TemporaryIssueResponse{UserID: result.UserID, Reused: result.Reused}
	if !result.ExpiresAt.IsZero() {
		response.ExpiresAt = &result.ExpiresAt
	}
	// A replay never exposes a secret, even if an adapter accidentally retains it.
	if !result.Reused {
		response.Password = result.Password
	}
	return response
}

var temporaryAdminErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrTemporaryPasswordDisabled, 404, "method_disabled", "temporary password disabled"),
	httpx.MatchError(accountdomain.ErrProvisionConflict, 409, "provisioning_conflict", "provisioning request conflict"),
	httpx.MatchError(accountdomain.ErrProvisionEmailExists, 409, "email_unavailable", "email unavailable"),
	httpx.MatchError(domain.ErrInvalidTemporaryPassword, 409, "target_unavailable", "temporary password target unavailable"),
	httpx.MatchError(domain.ErrTemporaryPasswordCooldown, 409, "issuance_cooldown", "issuance cooldown has not elapsed"),
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
	httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh password and MFA required"),
	{Target: domain.ErrRecoveryLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *TemporaryAdminHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "temporary_password_issuance", err, temporaryAdminErrors, dependencyFailure)
}
