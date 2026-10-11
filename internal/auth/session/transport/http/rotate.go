package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type rotationService interface {
	Rotate(context.Context, accountdomain.UserID, string) (*service.CreatedSession, error)
}

type RotationHandler struct {
	service rotationService
	log     *zap.Logger
}

func NewRotation(service rotationService, log *zap.Logger) *RotationHandler {
	return &RotationHandler{service: service, log: log}
}

// @Summary Rotate the current session token
// @Description Requires an allowed Origin and the current session cookie. Replaces the token once without extending deadlines or refreshing authentication. Concurrent rotations have one winner; serialize browser requests around rotation. A lost successful response requires a new login. No old-token grace period.
// @Tags Session
// @Param Origin header string true "Exact HTTPS origin from AUTH_ALLOWED_ORIGINS"
// @Success 204
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/session/rotate [post]
func (h *RotationHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	result, err := h.service.Rotate(r.Context(), auth.UserID, auth.TokenHash)
	if err != nil {
		// Do not clear cookies on a losing request: another rotation may have succeeded.
		httpx.RespondError(w, r, h.log, "rotate session", err, sessionErrors, dependencyFailure)
		return
	}
	SetSessionCookie(w, result.RawToken, result.ExpiresAt)
	w.WriteHeader(http.StatusNoContent)
}
