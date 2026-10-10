package http

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var recoveryLimit = httpx.ErrorRule{
	Target:   domain.ErrRecoveryLimited,
	Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"900"}}},
}

var forgotErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(accountdomain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
	recoveryLimit,
}

var resetErrors = []httpx.ErrorRule{
	recoveryLimit,
	httpx.MatchError(domain.ErrInvalidReset, 400, "invalid_reset", "invalid reset"),
	httpx.MatchError(domain.ErrPasswordConfirmation, 400, "password_mismatch", "passwords do not match"),
	{Match: passwordPolicyError, Response: passwordPolicyFailure},
}

func (h *RecoveryHandler) respondError(w http.ResponseWriter, r *http.Request, err error, operation string, rules []httpx.ErrorRule) {
	httpx.RespondError(w, r, h.log, operation, err, rules, dependencyFailure)
}
