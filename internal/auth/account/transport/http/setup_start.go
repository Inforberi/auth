package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SetupStartRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type SetupStartResponse struct {
	Token     string    `json:"token"`
	Secret    string    `json:"secret"`
	URI       string    `json:"uri"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// @Summary Start operator-controlled first administrator setup
// @Description Requires installation operator secret and allowed HTTPS Origin. Sends email code. Returns bounded setup token and TOTP enrollment data, not a login session. No user exists yet. A retry after one minute replaces previous intent.
// @Tags Setup
// @Accept json
// @Produce json
// @Param X-Setup-Token header string true "32-byte installation proof (base64url)"
// @Param body body SetupStartRequest true "First administrator credentials"
// @Success 202 {object} SetupStartResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/setup/start [post]
func (h *SetupHandler) Start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input SetupStartRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Start(r.Context(), service.SetupStartInput{OperatorSecret: r.Header.Get("X-Setup-Token"), Email: input.Email, Password: input.Password, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, SetupStartResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
