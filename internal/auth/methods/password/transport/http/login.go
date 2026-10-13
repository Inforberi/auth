package http

import (
	"net/http"

	"go.uber.org/zap"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type LoginByEmailRequest struct {
	Email    string `json:"email" binding:"required" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"ExamplePass1"`
} // @name password_http.LoginByEmailRequest

type LoginByEmailResponse struct {
	Status string `json:"status"`
} // @name password_http.LoginByEmailResponse

// @Summary login by email
// @Description Sets the Secure, HttpOnly, SameSite=Lax __Host-session cookie on success. Unverified users can sign in, but sensitive routes require a verified email. HTTPS and an allowed Origin are required. Invalid credentials return 400, not 401. SQL session issuance checks current account status and auth version.
// @Tags Auth
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Param body body LoginByEmailRequest true "login payload"
// @Success 200 {object} LoginByEmailResponse
// @Success 202 {object} mfahttp.ChallengeResponse "MFA required; browser binding cookie, no session issued"
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_credentials"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited; Retry-After: 60"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/login/email [post]
func (h *PasswordHandler) LoginByEmail(w http.ResponseWriter, r *http.Request) {
	var input LoginByEmailRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errInvalidJSON.code,
			errInvalidJSON.message,
		)
		return
	}

	login, err := h.service.Login(r.Context(), passwordservice.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		UserAgent: httpx.UserAgent(r),
		IP:        httpx.IP(r),
	})
	if err != nil {
		if mfahttp.RespondLoginError(w, r, h.log, err) {
			return
		}
		h.respondError(w, r, err, "login", loginClientErrors)
		return
	}

	if login.Challenge != nil {
		mfahttp.RespondChallenge(w, login.Challenge)
		return
	}
	sessionhttp.SetSessionCookie(w, login.Token, login.ExpiresAt)
	httpx.JSON(w, http.StatusOK, LoginByEmailResponse{Status: "ok"})
	h.log.Info("user logged in", zap.String("user_id", string(login.UserID)))
}
