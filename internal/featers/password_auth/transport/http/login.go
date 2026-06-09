package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"go.uber.org/zap"
)

var (
	errInvalidCredentials = errorBody{"invalid_credentials", "invalid email or password"}
)

var loginClientErrors = []clientError{
	{
		password_domain.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidCredentials,
	},
	{
		domain.ErrEmailInvalid,
		http.StatusBadRequest,
		errInvalidEmail,
	},
}

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
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_credentials"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
// @Router /auth/login/email [post]
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

	login, err := h.service.Login(r.Context(), password_domain.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		UserAgent: httpx.UserAgent(r),
		IP:        httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err, "login", loginClientErrors)
		return
	}

	httpx.SetSessionCookie(w, login.Token, login.ExpiresAt)
	httpx.JSON(w, http.StatusOK, LoginByEmailResponse{Status: "ok"})
	h.log.Info("user logged in", zap.String("user_id", string(login.UserID)))
}
