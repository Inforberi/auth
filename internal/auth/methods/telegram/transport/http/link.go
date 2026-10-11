package http

import (
	"net/http"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Start linking Telegram to the current account
// @Description Requires current session, exact Origin, verified email with permanent password and recent password reauthentication. Flow binds UUID and session hash; callback does not create a session or user. One identity per provider per account.
// @Tags Account
// @Produce json
// @Param Origin header string true "Allowed browser origin"
// @Success 200 {object} StartResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/link [post]
func (h *Handler) StartLink(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		h.respondError(w, r, accountdomain.ErrFreshAuthRequired)
		return
	}
	started, err := h.service.StartLink(r.Context(), auth.UserID, auth.TokenHash, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, started.Binding)
	httpx.JSON(w, 200, StartResponse{AuthorizationURL: started.URL})
}
