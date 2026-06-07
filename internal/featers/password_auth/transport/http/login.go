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

type LoginBadRequestError struct {
	Code    string `json:"code" enums:"invalid_json,email_required,password_required,invalid_email,invalid_credentials" example:"invalid_credentials"`
	Message string `json:"message" example:"invalid email or password"`
}

type LoginInternalError struct {
	Code    string `json:"code" enums:"internal_error" example:"internal_error"`
	Message string `json:"message" example:"internal error"`
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
// @Failure 400 {object} password_http.LoginBadRequestError
// @Failure 500 {object} password_http.LoginInternalError
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
	h.log.Info("user logged in", zap.String("user_id", string(login.UserID)))
	httpx.JSON(w, http.StatusOK, LoginByEmailResponse{Status: "ok"})
}
