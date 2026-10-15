package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type userLifecycleService interface {
	ChangeStatus(context.Context, accessservice.Principal, domain.StatusChange) (domain.AuthVersion, error)
	Delete(context.Context, accessservice.Principal, domain.AccountDeletion) (domain.AuthVersion, error)
}

type UserLifecycleHandler struct {
	service userLifecycleService
	log     *zap.Logger
}

func NewUserLifecycle(service userLifecycleService, log *zap.Logger) *UserLifecycleHandler {
	return &UserLifecycleHandler{service: service, log: log}
}

type UserLifecycleResponse struct {
	AuthVersion domain.AuthVersion `json:"authVersion" swaggertype:"integer"`
} // @name account_http.UserLifecycleResponse

var userLifecycleErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidStatusChange, 400, "invalid_status_change", "invalid status change"),
	httpx.MatchError(domain.ErrInvalidAccountDeletion, 400, "invalid_deletion", "invalid account deletion"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
	httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh password and MFA required"),
	httpx.MatchError(domain.ErrAccountNotFound, 404, "user_not_found", "user not found"),
	httpx.MatchError(domain.ErrAccountDeleted, 409, "account_deleted", "account deleted"),
	httpx.MatchError(domain.ErrAccountConflict, 409, "account_conflict", "account version or activation conflict"),
	httpx.MatchError(domain.ErrLastAdministrator, 409, "last_administrator", "last administrator must remain"),
}

func (h *UserLifecycleHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "user_lifecycle", err, userLifecycleErrors, dependencyFailure)
}
