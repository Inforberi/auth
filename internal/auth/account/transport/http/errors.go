package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var dependencyFailure = httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}

var verificationErrors = []httpx.ErrorRule{
	{Target: domain.ErrVerificationLimited, Response: httpx.Failure{
		Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}},
	}},
	httpx.MatchError(domain.ErrInvalidVerification, 400, "invalid_verification", "invalid verification"),
}

var resendErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrEmailRequired, 400, "invalid_email", "invalid email"),
	httpx.MatchError(domain.ErrEmailInvalid, 400, "invalid_email", "invalid email"),
}, verificationErrors...)

var verifiedErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrEmailUnverified, 403, "email_not_verified", "email not verified"),
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error, operation string, rules []httpx.ErrorRule) {
	httpx.RespondError(w, r, h.log, operation, err, rules, dependencyFailure)
}
