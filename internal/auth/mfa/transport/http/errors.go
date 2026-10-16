package mfahttp

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var mfaErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidCode, 400, "invalid_mfa", "invalid MFA proof"),
	httpx.MatchError(domain.ErrProofRequired, 403, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(domain.ErrRequiredByPolicy, 403, "mfa_required_by_policy", "MFA is required by administrative policy"),
	httpx.MatchError(domain.ErrConflict, 409, "mfa_conflict", "MFA state conflict"),
	httpx.MatchError(domain.ErrUnavailable, 503, "temporarily_unavailable", "temporarily unavailable"),
	httpx.MatchError(sessiondomain.ErrMFARequired, 503, "temporarily_unavailable", "temporarily unavailable"),
	{Target: domain.ErrLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func RespondLoginError(w http.ResponseWriter, r *http.Request, log *zap.Logger, err error) bool {
	failure := httpx.MapError(err, mfaErrors, httpx.Failure{})
	if failure.Status == 0 {
		return false
	}
	httpx.RespondError(w, r, log, "mfa_login", err, nil, failure)
	return true
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	if settingshttp.RespondPolicyError(w, r, h.log, err) {
		return
	}
	httpx.RespondError(w, r, h.log, "mfa", err, mfaErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}
