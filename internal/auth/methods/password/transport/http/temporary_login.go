package http

import (
	"net/http"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TemporaryLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
} // @name password_http.TemporaryLoginRequest

type TemporaryLoginResponse struct {
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
} // @name password_http.TemporaryLoginResponse

// @Summary Begin mandatory password setup
// @Description Optional temporary password profile. Returns only a short-lived password-setup token, never a session cookie. Repeated successful login replaces the previous setup token. Does not verify email or grant product access. Shares ordinary login rate limits.
// @Tags Auth
// @Accept json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Produce json
// @Param body body TemporaryLoginRequest true "email and temporary password"
// @Success 200 {object} TemporaryLoginResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_temporary_password"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/temporary-password/login [post]
func (h *TemporaryPasswordHandler) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input TemporaryLoginRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Login(r.Context(), input.Email, input.Password, httpx.IP(r))
	if err != nil {
		httpx.RespondError(w, r, h.log, "temporary password login", err, temporaryPasswordErrors, dependencyFailure)
		return
	}
	httpx.JSON(w, 200, TemporaryLoginResponse{Status: "password_change_required", Token: result.Token, ExpiresAt: result.ExpiresAt})
}
