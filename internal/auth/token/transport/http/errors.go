package http

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

var exchangeErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidRequest, 400, "invalid_token_request", "invalid token request"),
	httpx.MatchError(domain.ErrForbidden, 403, "forbidden", "scope not allowed"),
	httpx.MatchError(sessiondomain.ErrSessionNotFound, 401, "unauthorized", "unauthorized"),
	httpx.MatchError(sessiondomain.ErrSessionExpired, 401, "unauthorized", "unauthorized"),
	httpx.MatchError(sessiondomain.ErrMFARequired, 403, "mfa_required", "complete MFA login"),
	httpx.MatchError(accountdomain.ErrEmailUnverified, 403, "email_not_verified", "email not verified"),
	{Target: domain.ErrRateLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

func (h *Handler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "token_exchange", err, exchangeErrors, httpx.Failure{
		Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable", Headers: http.Header{"Retry-After": {"1"}},
	})
}

var introspectionErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrForbidden, 403, "forbidden", "audience not allowed"),
	{Target: domain.ErrRateLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
	{Target: authjwt.ErrBusy, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"1"}}}},
}

func (h *IntrospectionHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, nil, "token_introspection", err, introspectionErrors, httpx.Failure{
		Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable", Headers: http.Header{"Retry-After": {"1"}},
	})
}
