package password_http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"go.uber.org/zap"
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
	{domain.ErrEmailInvalid, http.StatusBadRequest, errInvalidEmail},
	{domain.ErrEmailRequired, http.StatusBadRequest, errEmailRequired},
	{password_domain.ErrEmailAlreadyExists, http.StatusConflict, errEmailAlreadyExists},
	{domain.ErrPasswordTooShort, http.StatusBadRequest, errPasswordTooShort},
	{domain.ErrPasswordTooLong, http.StatusBadRequest, errPasswordTooLong},
	{domain.ErrPasswordNoLetter, http.StatusBadRequest, errPasswordNoLetter},
	{domain.ErrPasswordNoDigit, http.StatusBadRequest, errPasswordNoDigit},
	{domain.ErrPasswordNoUpper, http.StatusBadRequest, errPasswordNoUpper},
}

type RegisterBadRequestError struct {
	Code    string `json:"code" enums:"invalid_json,email_required,password_required,invalid_email,password_too_short,password_too_long,password_no_letter,password_no_digit,password_no_upper_letter" example:"password_too_short"`
	Message string `json:"message" example:"password too short"`
}

type RegisterConflictError struct {
	Code    string `json:"code" enums:"email_already_exists" example:"email_already_exists"`
	Message string `json:"message" example:"email already exists"`
}

type RegisterInternalError struct {
	Code    string `json:"code" enums:"internal_error" example:"internal_error"`
	Message string `json:"message" example:"internal error"`
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
// @Failure 400 {object} password_http.RegisterBadRequestError
// @Failure 409 {object} password_http.RegisterConflictError
// @Failure 500 {object} password_http.RegisterInternalError
// @Router /auth/register/email [post]
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

	httpx.SetSessionCookie(w, register.Token, register.ExpiresAt)
	h.log.Info("user register in", zap.String("user_id", string(register.UserID)))
	httpx.JSON(w, http.StatusCreated, RegisterResponse{UserID: register.UserID})
}
