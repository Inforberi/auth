package http

import (
	"net/http"

	"go.uber.org/zap"

	emailmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/email/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var errInvalidCredentials = errorBody{"invalid_credentials", "invalid email or password"}

var loginClientErrors = []clientError{
	{
		passwordmodel.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidCredentials,
	},
	{
		emailmodel.ErrEmailInvalid,
		http.StatusBadRequest,
		errInvalidEmail,
	},
}

type LoginByEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
} // @name password_http.LoginByEmailRequest

type LoginByEmailResponse struct {
	Status string `json:"status"`
} // @name password_http.LoginByEmailResponse

// @Summary login by email
// @Description login by email/password
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body LoginByEmailRequest true "login payload"
// @Success 200 {object} LoginByEmailResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, email_required, password_required, invalid_email, invalid_credentials"
// @Failure 500 {object} httpx.ErrorResponse "code: internal_error"
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

	login, err := h.service.Login(r.Context(), passwordmodel.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		UserAgent: httpx.UserAgent(r),
		IP:        httpx.IP(r),
	})
	if err != nil {
		h.respondError(w, r, err, "login", loginClientErrors)
		return
	}

	sessionhttp.SetSessionCookie(w, login.Token, login.ExpiresAt)
	httpx.JSON(w, http.StatusOK, LoginByEmailResponse{Status: "ok"})
	h.log.Info("user logged in", zap.String("user_id", string(login.UserID)))
}
