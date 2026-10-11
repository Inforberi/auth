package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type reauthenticationService interface {
	Confirm(context.Context, accountdomain.UserID, string, string, string) (*service.ReauthenticationResult, error)
}

type ReauthenticationHandler struct {
	service reauthenticationService
	log     *zap.Logger
}

func NewReauthentication(service reauthenticationService, log *zap.Logger) *ReauthenticationHandler {
	return &ReauthenticationHandler{service: service, log: log}
}

type ReauthenticationRequest struct {
	Password string `json:"password"`
} // @name password_http.ReauthenticationRequest

type ReauthenticationResponse struct {
	ValidUntil time.Time `json:"validUntil"`
} // @name password_http.ReauthenticationResponse

var reauthenticationErrors = []httpx.ErrorRule{
	httpx.MatchError(accountdomain.ErrFreshAuthRequired, 401, "fresh_auth_required", "fresh authentication required"),
	httpx.MatchError(sessiondomain.ErrSessionNotFound, 401, "unauthorized", "unauthorized"),
	httpx.MatchError(sessiondomain.ErrSessionExpired, 401, "unauthorized", "unauthorized"),
	{Target: domain.ErrLoginLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}

// @Summary Confirm current password for sensitive actions
// @Description Requires current session cookie and allowed Origin. Atomically rotates the token and records password proof for this session only. Does not extend session deadlines, prove MFA or grant permissions. No old-token grace period; serialize requests around reauthentication. Lost successful response requires login. Password and token never returned in JSON.
// @Tags Session
// @Accept json
// @Produce json
// @Param Origin header string true "Exact HTTPS origin from AUTH_ALLOWED_ORIGINS"
// @Param body body ReauthenticationRequest true "current password"
// @Success 200 {object} ReauthenticationResponse
// @Failure 400 {object} httpx.ErrorResponse "code: invalid_json"
// @Failure 401 {object} httpx.ErrorResponse "codes: unauthorized, fresh_auth_required"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/reauthenticate/password [post]
func (h *ReauthenticationHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return
	}
	var input ReauthenticationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Confirm(r.Context(), auth.UserID, auth.TokenHash, input.Password, httpx.IP(r))
	if err != nil {
		httpx.RespondError(w, r, h.log, "reauthenticate password", err, reauthenticationErrors, dependencyFailure)
		return
	}
	sessionhttp.SetSessionCookie(w, result.Token, result.ExpiresAt)
	httpx.JSON(w, 200, ReauthenticationResponse{ValidUntil: result.ValidUntil})
}
