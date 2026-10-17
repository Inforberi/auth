package http

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ActivityService interface {
	Record(context.Context, accountdomain.UserID, string) (*service.ActivityResult, error)
}

type ActivityResponse struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

type ActivityHandler struct {
	service ActivityService
	log     *zap.Logger
}

func NewActivity(svc ActivityService, log *zap.Logger) *ActivityHandler {
	return &ActivityHandler{service: svc, log: log}
}

// @Summary Report interactive session activity
// @Description Call only after user interaction, never from polling or timers alone. Administrative sessions use a stored bounded idle window; ordinary sessions are unchanged. Does not renew primary, password or MFA proof or the absolute deadline. No body or client timestamps.
// @Tags Sessions
// @Produce json
// @Success 200 {object} ActivityResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/session/activity [post]
func (h *ActivityHandler) Record(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	result, err := h.service.Record(r.Context(), auth.UserID, auth.TokenHash)
	if err != nil {
		httpx.RespondError(w, r, h.log, "session_activity", err, sessionErrors, dependencyFailure)
		return
	}
	if result.Extended {
		raw, err := GetSessionCookie(r)
		if err != nil {
			unauthorized(w)
			return
		}
		SetSessionCookie(w, raw, result.ExpiresAt)
	}
	httpx.JSON(w, http.StatusOK, ActivityResponse{ExpiresAt: result.ExpiresAt})
}
