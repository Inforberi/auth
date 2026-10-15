package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var accessErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrLastAdministrator, 409, "last_administrator", "last usable administrator must remain"),
	httpx.MatchError(domain.ErrInvalidRole, 400, "invalid_role", "invalid role"),
	httpx.MatchError(domain.ErrInvalidPermission, 400, "invalid_permission", "invalid permission"),
	httpx.MatchError(domain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh password and MFA required"),
	httpx.MatchError(domain.ErrForbidden, 403, "forbidden", "forbidden"),
	httpx.MatchError(domain.ErrRoleNotFound, 404, "role_not_found", "role not found"),
	httpx.MatchError(domain.ErrConflict, 409, "access_conflict", "access changed; reload and retry"),
	httpx.MatchError(domain.ErrTargetUnavailable, 409, "target_unavailable", "target unavailable"),
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "access", err, accessErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
