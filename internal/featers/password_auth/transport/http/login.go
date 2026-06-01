package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"go.uber.org/zap"
)

type LoginByEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginByEmailResponse struct {
	Status string `json:"status"`
}

// @Summary login by email
// @Description login by email/password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body LoginByEmailRequest true "login payload"
// @Success 200 {object} LoginByEmailResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 500 {object} httpx.ErrorResponse
// @Router /auth/login/email [post]
func (h *PasswordHandler) LoginByEmail(w http.ResponseWriter, r *http.Request) {
	var input LoginByEmailRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			CodeInvalidJSON,
			"Invalid JSON",
		)
		return
	}

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

	login, err := h.service.Login(r.Context(), password_domain.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		UserAgent: userAgent,
		IP:        ip,
	})

	logger := h.log.With(
		zap.String("ip", ip),
		zap.String("user_agent", userAgent),
	)

	if err != nil {
		errs := mapError(err)

		if errs.Status >= 500 {
			logger.Error("login failed", zap.Error(err))
		} else {
			logger.Warn("login failed", zap.Error(err))
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
		login.Token,
		login.ExpiresAt,
	)

	logger.Info("user logged in", zap.String("user_id", string(login.UserID)))

	httpx.JSON(
		w,
		http.StatusOK,
		LoginByEmailResponse{
			Status: "ok",
		},
	)
}
