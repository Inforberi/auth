package http

import (
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RegisterRequest struct {
	Email    string `json:"email" binding:"required" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"ExamplePass1"`
} // @name password_http.RegisterRequest

type RegisterResponse struct {
	VerificationRequired bool                 `json:"verificationRequired,omitempty"`
	UserID               accountdomain.UserID `json:"userID" swaggertype:"string" binding:"required"`
} // @name password_http.RegisterResponse

// @Summary Register by email
// @Description Enforces current public method/registration policy. Required email verification returns 201 with verificationRequired=true and no session cookie. Optional queues verification and issues a session; disabled does not queue automatic verification or mark the address verified. Account and queued mail commit atomically; session issuance is separate, so an error does not prove account rollback. A committed retry returns 409, never automatic login. HTTPS and allowed Origin are required.
// @Tags Auth
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Failure 403 {object} httpx.ErrorResponse "codes: invalid_origin, registration_disabled"
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Param body body RegisterRequest true "Register payload"
// @Success 201 {object} RegisterResponse
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, password_too_short, password_too_long, password_no_letter, password_no_digit, password_no_upper_letter"
// @Failure 409 {object} httpx.ErrorResponse "code: email_already_exists"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Router /api/v1/auth/register/email [post]
func (h *PasswordHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input RegisterRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, http.StatusBadRequest, errInvalidJSON.code, errInvalidJSON.message)
		return
	}

	register, err := h.service.Register(
		r.Context(),
		input.Email,
		input.Password,
		httpx.UserAgent(r),
		httpx.IP(r),
	)
	if err != nil {
		h.respondError(w, r, err, "register", registerClientErrors)
		return
	}

	if register.Token != "" {
		sessionhttp.SetSessionCookie(w, register.Token, register.ExpiresAt)
	}
	h.log.Info("user register in", zap.String("user_id", string(register.UserID)))
	httpx.JSON(w, http.StatusCreated, RegisterResponse{UserID: register.UserID, VerificationRequired: register.VerificationRequired})
}
