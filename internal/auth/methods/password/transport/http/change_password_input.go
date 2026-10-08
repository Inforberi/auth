package http

import (
	"errors"
	"net/http"

	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

var (
	errConfirmPassword        = errorBody{"password_mismatch", "passwords do not match"}
	errInvalidEmailOrPassword = errorBody{"invalid_email_or_password", "invalid email or password"}
	errSamePassword           = errorBody{"same_password", "same password"}
	errEmptyNewPassword       = errorBody{"empty_new_password", "new password cannot be empty"}
	errEmptyOldPassword       = errorBody{"empty_old_password", "old password cannot be empty"}
	errEmptyConfirmPassword   = errorBody{"empty_confirm_password", "confirmation password cannot be empty"}
)

var (
	ErrEmptyOldPassword     = errors.New("empty_old_password")
	ErrEmptyNewPassword     = errors.New("empty_new_password")
	ErrEmptyConfirmPassword = errors.New("empty_confirm_password")
	ErrPasswordMismatch     = errors.New("password_mismatch")
)

var changePasswordErrors = []clientError{
	{
		passworddomain.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidEmailOrPassword,
	},
	{
		passworddomain.ErrSamePassword,
		http.StatusBadRequest,
		errSamePassword,
	},
	{
		passworddomain.ErrNotFound,
		http.StatusNotFound,
		errNotFound,
	},
	{
		ErrEmptyNewPassword,
		http.StatusBadRequest,
		errEmptyNewPassword,
	},
	{
		ErrEmptyOldPassword,
		http.StatusBadRequest,
		errEmptyOldPassword,
	},
	{
		ErrEmptyConfirmPassword,
		http.StatusBadRequest,
		errEmptyConfirmPassword,
	},
	{
		ErrPasswordMismatch,
		http.StatusBadRequest,
		errConfirmPassword,
	},
}

type ChangePasswordRequest struct {
	OldPassword     string `json:"oldPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
} // @name password_http.ChangePasswordRequest

type ChangePasswordResponse struct {
	Status string
} // @name password_http.ChangePasswordResponse

func validateChangePasswordInput(input ChangePasswordRequest) error {
	switch {
	case input.OldPassword == "":
		return ErrEmptyOldPassword
	case input.NewPassword == "":
		return ErrEmptyNewPassword
	case input.ConfirmPassword == "":
		return ErrEmptyConfirmPassword
	case input.NewPassword != input.ConfirmPassword:
		return ErrPasswordMismatch
	}
	return nil
}
