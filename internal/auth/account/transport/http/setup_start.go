package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type SetupStartRequest struct {
	Email    string                 `json:"email"`
	Password string                 `json:"password"`
	MFAMode  settingsdomain.MFAMode `json:"mfaMode,omitempty" swaggertype:"string" enums:"optional,administrators,required"`
}
type SetupStartResponse struct {
	Token     string    `json:"token"`
	Secret    string    `json:"secret,omitempty"`
	URI       string    `json:"uri,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// @Summary Start operator-controlled first administrator setup
// @Description Requires installation operator secret and allowed HTTPS Origin. Pins mfaMode in encrypted intent; omitted mode defaults to administrators. Optional returns no TOTP enrollment data. Sends email code, creates no user or session. A retry after one minute replaces previous intent.
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
	result, err := h.service.Start(r.Context(), service.SetupStartInput{OperatorSecret: r.Header.Get("X-Setup-Token"), Email: input.Email, Password: input.Password, MFAMode: input.MFAMode, IP: httpx.IP(r)})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 202, SetupStartResponse{Token: result.Token, Secret: result.Secret, URI: result.URI, ExpiresAt: result.ExpiresAt})
}
