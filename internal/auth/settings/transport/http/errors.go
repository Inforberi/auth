package http

import (
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

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
