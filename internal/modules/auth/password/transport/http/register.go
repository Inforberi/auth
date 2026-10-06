package http

import (
	"net/http"

	"go.uber.org/zap"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	emailmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/email/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var (
	errEmailAlreadyExists = errorBody{"email_already_exists", "email already exists"}
	errPasswordTooShort   = errorBody{"password_too_short", "password too short"}
	errPasswordTooLong    = errorBody{"password_too_long", "password too long"}
	errPasswordNoLetter   = errorBody{"password_no_letter", "password must contain at least one letter"}
	errPasswordNoDigit    = errorBody{"password_no_digit", "password must contain at least one digit"}
	errPasswordNoUpper    = errorBody{"password_no_upper_letter", "password must contain at least one uppercase letter"}
)

var registerClientErrors = []clientError{
	{emailmodel.ErrEmailInvalid, http.StatusBadRequest, errInvalidEmail},
	{emailmodel.ErrEmailRequired, http.StatusBadRequest, errEmailRequired},
	{passwordmodel.ErrEmailAlreadyExists, http.StatusConflict, errEmailAlreadyExists},
	{passwordmodel.ErrPasswordTooShort, http.StatusBadRequest, errPasswordTooShort},
	{passwordmodel.ErrPasswordTooLong, http.StatusBadRequest, errPasswordTooLong},
	{passwordmodel.ErrPasswordNoLetter, http.StatusBadRequest, errPasswordNoLetter},
	{passwordmodel.ErrPasswordNoDigit, http.StatusBadRequest, errPasswordNoDigit},
	{passwordmodel.ErrPasswordNoUpper, http.StatusBadRequest, errPasswordNoUpper},
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
} // @name password_http.RegisterRequest

type RegisterResponse struct {
	UserID accountmodel.UserID `json:"userID" swaggertype:"string"`
} // @name password_http.RegisterResponse

// @Summary Register by email
// @Description Creates a new user account using email/password.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body RegisterRequest true "Register payload"
// @Success 201 {object} RegisterResponse
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

	if input.Email == "" {
		httpx.Error(w, http.StatusBadRequest, errEmailRequired.code, errEmailRequired.message)
		return
	}

	if input.Password == "" {
		httpx.Error(w, http.StatusBadRequest, errPasswordRequired.code, errPasswordRequired.message)
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

	sessionhttp.SetSessionCookie(w, register.Token, register.ExpiresAt)
	h.log.Info("user register in", zap.String("user_id", string(register.UserID)))
	httpx.JSON(w, http.StatusCreated, RegisterResponse{UserID: register.UserID})
}
