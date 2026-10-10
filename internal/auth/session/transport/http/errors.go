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

var dependencyFailure = httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}

var managementErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidSessionID, 400, "invalid_session_id", "invalid session ID"),
	httpx.MatchError(domain.ErrOwnedSessionNotFound, 404, "session_not_found", "session not found"),
}, sessionErrors...)

func (m *Middleware) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, m.log, "validate session", err, sessionErrors, dependencyFailure)
}
