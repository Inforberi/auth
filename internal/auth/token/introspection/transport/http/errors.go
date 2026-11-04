package tokenintrospectionhttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

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
