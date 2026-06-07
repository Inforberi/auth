package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"go.uber.org/zap"
)

// only for docs
type RegisterBadRequestError struct{
	code string `json:"code" enums:"invalid_json,email_required,errPasswordRequired,"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	UserID domain.UserID `json:"userID"`
}

// @Summary Register by email
// @Description Creates a new user account using email/password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body RegisterRequest true "Register payload"
// @Success 201 {object} RegisterResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 500 {object} httpx.ErrorResponse
// @Router /auth/register/email [post]
func (h *PasswordHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input RegisterRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errInvalidJSON.code,
			errInvalidJSON.message,
		)
		return
	}

	if input.Email == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errEmailRequired.code,
			errEmailRequired.message,
		)
		return
	}

	if input.Password == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errPasswordRequired.code,
			errPasswordRequired.message,
		)
		return
	}

	userAgent := httpx.UserAgent(r)
	ip := httpx.IP(r)

	register, err := h.service.Register(
		r.Context(),
		input.Email,
		input.Password,
		userAgent,
		ip,
	)

	if err != nil {
		h.respondError(
			w,
			r,
			err,
			"register",
		)
		return
	}

	httpx.SetSessionCookie(
		w,
		register.Token,
		register.ExpiresAt,
	)

	h.log.Info("user register in", zap.String("user_id", string(register.UserID)))

	httpx.JSON(
		w,
		http.StatusCreated,
		RegisterResponse{
			UserID: register.UserID,
		},
	)
}
