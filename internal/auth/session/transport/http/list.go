package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SessionResponse struct {
	CredentialProfile string    `json:"credentialProfile" example:"api" enums:"browser,api"`
	ID                string    `json:"id"`
	Current           bool      `json:"current"`
	UserAgent         string    `json:"userAgent"`
	IPAddress         string    `json:"ipAddress"`
	CreatedAt         time.Time `json:"createdAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
}

type SessionsResponse struct {
	Sessions   []SessionResponse `json:"sessions"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// @Summary List own active sessions
// @Description Up to 50 items ordered by creation time and public UUID descending; pass nextCursor as before. No session secrets are returned.
// @Tags Session
// @Produce json
// @Param before query string false "Public session UUID cursor"
// @Success 200 {object} SessionsResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/sessions [get]
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	auth, ok := requireAuth(w, r)
	if !ok {
		return
	}
	page, err := h.service.List(r.Context(), auth.UserID, auth.TokenHash, r.URL.Query().Get("before"))
	if err != nil {
		h.respondError(w, r, "list sessions", err)
		return
	}
	response := SessionsResponse{Sessions: make([]SessionResponse, 0, len(page.Sessions)), NextCursor: page.NextCursor}
	for _, session := range page.Sessions {
		response.Sessions = append(response.Sessions, SessionResponse{
			ID: session.ID, CredentialProfile: session.CredentialProfile, Current: session.ID == auth.SessionID, UserAgent: session.UserAgent,
			IPAddress: session.IPAddress, CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
		})
	}
	httpx.JSON(w, 200, response)
}
