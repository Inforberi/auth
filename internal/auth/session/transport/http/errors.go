package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var sessionErrors = []httpx.ErrorRule{
	httpx.MatchError(domain.ErrSessionNotFound, 401, "unauthorized", "unauthorized"),
	httpx.MatchError(domain.ErrSessionExpired, 401, "unauthorized", "unauthorized"),
}

func (m *Middleware) respondError(w http.ResponseWriter, r *http.Request, err error) {
	fallback := httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}
	httpx.RespondError(w, r, m.log, "validate session", err, sessionErrors, fallback)
}
