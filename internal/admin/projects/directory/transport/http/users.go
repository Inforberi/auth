package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	cataloghttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type userService interface {
	ListProjectUsers(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountservice.UserListInput) (accountservice.UserPage, error)
	ReadProjectUser(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID) (accountservice.UserDetail, error)
}

type UserHandler struct {
	createUser CreateUser
	lifecycle  Lifecycle
	service    userService
	log        *zap.Logger
}

func NewUsers(service userService, log *zap.Logger) *UserHandler {
	return &UserHandler{service: service, log: log}
}

var projectUserErrors = append(append(accounthttp.UserDirectoryErrorRules(), cataloghttp.CatalogErrorRules()...),
	httpx.MatchError(accountdomain.ErrProvisionDisabled, 404, "method_disabled", "provisioning disabled"),
	httpx.MatchError(passworddomain.ErrTemporaryPasswordDisabled, 404, "method_disabled", "temporary password disabled"),
	httpx.MatchError(passworddomain.ErrInvalidTemporaryPassword, 409, "target_unavailable", "temporary password target unavailable"),
	httpx.MatchError(passworddomain.ErrTemporaryPasswordCooldown, 409, "issuance_cooldown", "issuance cooldown has not elapsed"),
	httpx.MatchError(accountdomain.ErrEmailBindingConflict, 409, "email_binding_conflict", "email binding unavailable"),
	httpx.ErrorRule{Target: passworddomain.ErrRecoveryLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	httpx.MatchError(accountdomain.ErrProvisionEmailExists, 409, "email_unavailable", "email unavailable"),
	httpx.ErrorRule{Target: accountdomain.ErrVerificationLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	httpx.MatchError(accountdomain.ErrAccountConflict, 409, "account_conflict", "account version or operation conflict"),
	httpx.MatchError(accountdomain.ErrAccountDeleted, 409, "account_deleted", "account deleted"),
	httpx.MatchError(accountdomain.ErrLastAdministrator, 409, "last_administrator", "last administrator cannot be removed"))

func (h *UserHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "platform_users", err, projectUserErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
