package http

import (
	"net/http"

	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var settingsErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidPolicy, 400, "invalid_auth_policy", "invalid authentication policy"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "auth_policy_conflict", "authentication policy changed; reload and retry"),
	httpx.MatchError(domain.ErrMethodNotReady, 409, "auth_method_not_ready", "login adapter not ready on this instance"),
	httpx.MatchError(accessdomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh password and MFA required"),
	httpx.MatchError(accessdomain.ErrForbidden, 403, "forbidden", "forbidden"),
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "auth_settings", err, settingsErrors,
		httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

var policyErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrMethodDisabled, 404, "method_disabled", "login method disabled"),
	httpx.MatchError(domain.ErrRegistrationDisabled, 403, "registration_disabled", "public registration disabled"),
	httpx.MatchError(domain.ErrPolicyUnavailable, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(accountdomain.ErrEmailUnverified, 403, "email_not_verified", "email not verified"),
}

func RespondPolicyError(w http.ResponseWriter, r *http.Request, log *zap.Logger, err error) bool {
	failure := httpx.MapError(err, policyErrors, httpx.Failure{})
	if failure.Status == 0 {
		return false
	}
	httpx.RespondError(w, r, log, "auth_policy", err, nil, failure)
	return true
}
