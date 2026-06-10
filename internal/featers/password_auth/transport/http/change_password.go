package password_http

import (
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
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
		password_domain.ErrInvalidEmailOrPassword,
		http.StatusBadRequest,
		errInvalidEmailOrPassword,
	},
	{
		password_domain.ErrSamePassword,
		http.StatusBadRequest,
		errSamePassword,
	},
	{
		password_domain.ErrNotFound,
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
}

type ChangePasswordResponse struct {
	Status string
}

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

func (p *PasswordHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	auth, ok := httpx.GetAuthContext(r.Context())
	if !ok {
		panic("get auth form context")
	}

	// decode json
	var input ChangePasswordRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(
			w,
			http.StatusBadRequest,
			errInvalidJSON.code,
			errInvalidJSON.message,
		)
		return
	}

	if err := validateChangePasswordInput(input); err != nil {
		p.respondError(w, r, err, "change password", changePasswordErrors)
		return
	}

	// call service
	err := p.service.ChangePassword(
		r.Context(),
		auth.UserID,
		auth.TokenHash,
		input.OldPassword,
		input.NewPassword,
	)
	if err != nil {
		p.respondError(w, r, err, "change password", changePasswordErrors)
		return
	}

	httpx.JSON(
		w,
		http.StatusOK,
		ChangePasswordResponse{Status: "ok"},
	)
	p.log.Info("user change password")
}
