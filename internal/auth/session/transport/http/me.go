package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type MeResponse struct {
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
}

// @Summary Get authenticated user and current session IDs
// @Description Requires __Host-session cookie. Returns IDs only; profile and contact management are separate features.
// @Tags Session
// @Produce json
// @Success 200 {object} MeResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/me [get]
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	httpx.JSON(w, 200, MeResponse{UserID: string(auth.UserID), SessionID: auth.SessionID})
}
