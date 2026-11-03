package passwordhttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var recoveryLimit = httpx.ErrorRule{
	Target:   domain.ErrRecoveryLimited,
	Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"900"}}},
}
