package register_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"go.uber.org/zap"
)

type RegisterByEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterByEmailResponse struct {
	UserID domain.UserID `json:"userID"`
}

// @Summary Register by email
// @Description Creates a new user account using email/password
// @Tags auth
// @Accept json
// @Produce json
// @Param body body RegisterByEmailRequest true "Register payload"
// @Success 201 {object} RegisterByEmailResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 500 {object} httpx.ErrorResponse
// @Router /auth/register/email [post]
func (h *RegisterHandler) RegisterByEmail(w http.ResponseWriter, r *http.Request) {
	// decode json
	var input RegisterByEmailRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeInvalidJSON,
			"Invalid JSON",
		)
		return
	}

	// validate request
	if input.Email == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeEmailRequired,
			"Email required",
		)
		return
	}

	if input.Password == "" {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodePasswordRequired,
			"Password required",
		)
		return
	}

	userAgent := httpx.UserAgent(r)
	ip := httpx.IP(r)

	// call service
	register, err := h.service.RegisterByEmail(
		r.Context(),
		input.Email,
		input.Password,
		userAgent,
		ip,
	)
	if err != nil {
		errs := mapError(err)

		logger := h.log.With(
			zap.String("email", input.Email),
			zap.String("ip", ip),
		)

		if errs.Status >= 500 {
			logger.Error(
				"register failed",
				zap.Error(err),
			)
		} else {
			logger.Warn(
				"register failed",
				zap.Error(err),
			)
		}

		httpx.Error(
			w,
			errs.Status,
			errs.Code,
			errs.Message,
		)
		return
	}

	httpx.SetSessionCookie(
		w,
		register.Token,
		register.ExpiresAt,
	)

	// write response
	httpx.JSON(
		w,
		http.StatusCreated,
		RegisterByEmailResponse{
			UserID: register.UserID,
		},
	)
}
